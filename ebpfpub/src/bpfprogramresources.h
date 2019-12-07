#pragma once

#include "bpfmap.h"
#include "bufferstorage.h"

namespace ebpfpub {
using EventMap = BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;
using StackMap = BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

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
} // namespace ebpfpub
