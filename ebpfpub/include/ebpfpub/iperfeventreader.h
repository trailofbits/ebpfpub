/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <atomic>
#include <memory>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/isyscalltracepoint.h>

#include <tob/ebpf/perfeventarray.h>

namespace tob::ebpfpub {
class IPerfEventReader {
public:
  using Ref = std::unique_ptr<IPerfEventReader>;

  static StringErrorOr<Ref> create(ebpf::PerfEventArray &perf_event_array,
                                   IBufferStorage &buffer_storage);

  IPerfEventReader() = default;
  virtual ~IPerfEventReader() = default;

  virtual void insert(ISyscallTracepoint::Ref syscall_tracepoint) = 0;

  virtual SuccessOrStringError
  exec(std::atomic_bool &terminate,
       void (*callback)(const ISyscallTracepoint::EventList &)) = 0;

  IPerfEventReader(const IPerfEventReader &) = delete;
  IPerfEventReader &operator=(const IPerfEventReader &) = delete;
};
} // namespace tob::ebpfpub
