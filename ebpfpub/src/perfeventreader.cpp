/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "perfeventreader.h"
#include "bufferreader.h"
#include "syscalltracepoint.h"

#include <unordered_map>
#include <vector>

#include <tob/ebpf/perfeventarray.h>

namespace tob::ebpfpub {
struct PerfEventReader::PrivateData final {
  PrivateData(ebpf::PerfEventArray &perf_event_array_,
              IBufferStorage &buffer_storage_)
      : perf_event_array(perf_event_array_), buffer_storage(buffer_storage_) {}

  ebpf::PerfEventArray &perf_event_array;
  IBufferStorage &buffer_storage;

  std::unordered_map<std::uint32_t, ISyscallTracepoint::Ref>
      syscall_tracepoint_map;
};

PerfEventReader::~PerfEventReader() {}

void PerfEventReader::insert(ISyscallTracepoint::Ref syscall_tracepoint) {
  auto event_identifier = syscall_tracepoint->eventIdentifier();

  d->syscall_tracepoint_map.insert(
      {event_identifier, std::move(syscall_tracepoint)});
}

SuccessOrStringError
PerfEventReader::exec(std::atomic_bool &terminate,
                      void (*callback)(const ISyscallTracepoint::EventList &)) {

  for (auto &p : d->syscall_tracepoint_map) {
    auto &syscall_tracepoint_ref = p.second;

    auto &syscall_tracepoint =
        *static_cast<SyscallTracepoint *>(syscall_tracepoint_ref.get());

    auto success_exp = syscall_tracepoint.start();
    if (success_exp.failed()) {
      return success_exp.error();
    }
  }

  std::vector<std::uint8_t> event_buffer = {};

  while (!terminate) {
    // Read the data from the perf event array
    if (!d->perf_event_array.read(event_buffer)) {
      continue;
    }

    if (event_buffer.empty()) {
      continue;
    }

    // Attempt to interpret the data we received
    auto buffer_reader = BufferReader(event_buffer.data(), event_buffer.size());

    while (buffer_reader.availableBytes() > 0U) {
      if (buffer_reader.availableBytes() <= 8U) {
        break;
      }

      auto event_entry_size = buffer_reader.peekU32(0U);
      auto event_identifier = buffer_reader.peekU32(4U);

      if (event_entry_size > buffer_reader.availableBytes()) {
        break;
      }

      auto syscall_tracepoint_it =
          d->syscall_tracepoint_map.find(event_identifier);

      if (syscall_tracepoint_it == d->syscall_tracepoint_map.end()) {
        buffer_reader.skipBytes(event_entry_size);
        break;
      }

      auto &syscall_ref = *static_cast<SyscallTracepoint *>(
          syscall_tracepoint_it->second.get());

      auto start_offset = buffer_reader.offset();

      auto event_list_exp = syscall_ref.parseEvents(buffer_reader);
      if (!event_list_exp.succeeded()) {
        buffer_reader.setOffset(start_offset);
        buffer_reader.skipBytes(event_entry_size);
        continue;
      }

      auto event_list = event_list_exp.takeValue();
      callback(event_list);
    }

    event_buffer.clear();
  }

  for (auto &p : d->syscall_tracepoint_map) {
    auto &syscall_tracepoint_ref = p.second;

    auto &syscall_tracepoint =
        *static_cast<SyscallTracepoint *>(syscall_tracepoint_ref.get());

    syscall_tracepoint.stop();
  }

  return {};
}

PerfEventReader::PerfEventReader(ebpf::PerfEventArray &perf_event_array,
                                 IBufferStorage &buffer_storage)
    : d(new PrivateData(perf_event_array, buffer_storage)) {}

StringErrorOr<PerfEventReader::Ref>
IPerfEventReader::create(ebpf::PerfEventArray &perf_event_array,
                         IBufferStorage &buffer_storage) {

  try {
    return Ref(new PerfEventReader(perf_event_array, buffer_storage));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
