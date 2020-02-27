/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/ifunctionserializer.h>

#include <tob/ebpf/perfeventarray.h>
#include <tob/ebpf/structure.h>

namespace tob::ebpfpub {
class IFunctionTracer {
public:
  using Ref = std::unique_ptr<IFunctionTracer>;

  static StringErrorOr<Ref> createFromSyscallTracepoint(
      const std::string &name, IBufferStorage &buffer_storage,
      ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size);

  static StringErrorOr<IFunctionTracer::Ref> createFromKprobe(
      const std::string &name, const ebpf::Structure &args,
      IBufferStorage &buffer_storage, ebpf::PerfEventArray &perf_event_array,
      std::size_t event_map_size, IFunctionSerializer::Ref serializer);

  static StringErrorOr<IFunctionTracer::Ref>
  createFromUprobe(const std::string &name, const std::string &path,
                   const ebpf::Structure &args, IBufferStorage &buffer_storage,
                   ebpf::PerfEventArray &perf_event_array,
                   std::size_t event_map_size,
                   IFunctionSerializer::Ref serializer);

  IFunctionTracer() = default;
  virtual ~IFunctionTracer() = default;

  virtual const std::string &name() const = 0;
  virtual std::uint32_t eventIdentifier() const = 0;
  virtual std::string ir() const = 0;

  IFunctionTracer(const IFunctionTracer &) = delete;
  IFunctionTracer &operator=(const IFunctionTracer &) = delete;
};
} // namespace tob::ebpfpub
