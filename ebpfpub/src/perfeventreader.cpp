/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "perfeventreader.h"
#include "functiontracer.h"

#include <unordered_map>
#include <vector>

#include <tob/ebpf/bufferreader.h>
#include <tob/ebpf/perfeventarray.h>

namespace tob::ebpfpub {
struct PerfEventReader::PrivateData final {
  PrivateData(ebpf::PerfEventArray &perf_event_array_)
      : perf_event_array(perf_event_array_) {}

  ebpf::PerfEventArray &perf_event_array;
  ebpf::BufferReader::Ptr buffer_reader;

  std::unordered_map<std::uint64_t, IFunctionTracer::Ref> function_tracer_map;
};

PerfEventReader::~PerfEventReader() {}

void PerfEventReader::insert(IFunctionTracer::Ref function_tracer) {
  auto event_identifier = function_tracer->eventIdentifier();

  d->function_tracer_map.insert({event_identifier, std::move(function_tracer)});
}

SuccessOrStringError PerfEventReader::exec(const std::chrono::seconds &timeout,
                                           Callback callback) {

  ErrorCounters error_counters = {};
  ebpf::PerfEventArray::BufferList event_buffer_list;

  if (!d->perf_event_array.read(event_buffer_list,
                                error_counters.invalid_probe_output,
                                error_counters.lost_events, timeout)) {

    return StringError::create("Failed to read from the perf event array");
  }

  for (const auto &event_buffer : event_buffer_list) {
    d->buffer_reader->reset(event_buffer);
    d->buffer_reader->skipBytes(ebpf::kPerfEventHeaderSize +
                                sizeof(std::uint32_t));

    try {
      for (;;) {
        if (d->buffer_reader->availableBytes() <= 12U) {
          ++error_counters.invalid_probe_output;
          break;
        }

        auto event_entry_size = d->buffer_reader->peekU32(0U);
        auto event_identifier = d->buffer_reader->peekU64(4U);

        if (event_entry_size > d->buffer_reader->availableBytes()) {
          ++error_counters.invalid_probe_output;
          break;
        }

        auto function_tracer_it = d->function_tracer_map.find(event_identifier);
        if (function_tracer_it == d->function_tracer_map.end()) {
          d->buffer_reader->skipBytes(event_entry_size);
          ++error_counters.invalid_event;
          break;
        }

        auto &tracer =
            *static_cast<FunctionTracer *>(function_tracer_it->second.get());

        auto event_list_exp = tracer.parseEventData(*d->buffer_reader.get());
        if (!event_list_exp.succeeded()) {
          ++error_counters.invalid_event_data;
          break;
        }

        auto event_list = event_list_exp.takeValue();
        callback(event_list, error_counters);

        if (d->buffer_reader->availableBytes() == 0U) {
          break;
        }
      }

    } catch (const ebpf::BufferReader::ReadError &) {
      ++error_counters.invalid_event_data;
    }
  }

  if (error_counters.invalid_probe_output != 0U ||
      error_counters.lost_events != 0U) {
    callback({}, error_counters);
  }

  return {};
}

PerfEventReader::PerfEventReader(ebpf::PerfEventArray &perf_event_array)
    : d(new PrivateData(perf_event_array)) {

  auto buffer_reader_exp = ebpf::BufferReader::create();
  if (!buffer_reader_exp.succeeded()) {
    throw buffer_reader_exp.error();
  }

  d->buffer_reader = buffer_reader_exp.takeValue();
}

StringErrorOr<PerfEventReader::Ref>
IPerfEventReader::create(ebpf::PerfEventArray &perf_event_array) {

  try {
    return Ref(new PerfEventReader(perf_event_array));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
