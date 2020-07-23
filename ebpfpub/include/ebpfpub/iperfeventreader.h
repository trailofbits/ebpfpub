/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>

#include <ebpfpub/ifunctiontracer.h>

#include <tob/ebpf/perfeventarray.h>

namespace tob::ebpfpub {
class IPerfEventReader {
public:
  struct ErrorCounters final {
    std::size_t invalid_probe_output{0U};
    std::size_t invalid_event{0U};
    std::size_t invalid_event_data{0U};
    std::size_t lost_events{0U};
  };

  using Ref = std::unique_ptr<IPerfEventReader>;
  using Callback = std::function<void(const IFunctionTracer::EventList &,
                                      const ErrorCounters &)>;

  static StringErrorOr<Ref> create(ebpf::PerfEventArray &perf_event_array);

  IPerfEventReader() = default;
  virtual ~IPerfEventReader() = default;

  virtual void insert(IFunctionTracer::Ref function_tracer) = 0;
  virtual SuccessOrStringError exec(const std::chrono::seconds &timeout,
                                    Callback callback) = 0;

  IPerfEventReader(const IPerfEventReader &) = delete;
  IPerfEventReader &operator=(const IPerfEventReader &) = delete;
};
} // namespace tob::ebpfpub
