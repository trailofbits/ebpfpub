/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "bufferstorage.h"

#include <tob/ebpf/bpfmap.h>

namespace tob::ebpfpub {
using EventMap = ebpf::BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;
using StackMap = ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

class BPFProgramResources final {
public:
  BPFProgramResources(StackMap::Ref event_stack_map,
                      StackMap::Ref buffer_stack_map, EventMap::Ref event_map);
  BPFProgramResources();
  ~BPFProgramResources();

  StackMap &eventStackMap();
  StackMap &bufferStackMap();
  EventMap &eventMap();

  BPFProgramResources(BPFProgramResources &&other);
  BPFProgramResources &operator=(BPFProgramResources &&other);

  BPFProgramResources(const BPFProgramResources &) = delete;
  BPFProgramResources &operator=(const BPFProgramResources &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

// clang-format off
static_assert(
  std::is_move_constructible<BPFProgramResources>::value &&
  std::is_move_assignable<BPFProgramResources>::value,

  "BPFProgramResources must be movable"
);
// clang-format on
} // namespace tob::ebpfpub
