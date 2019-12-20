/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "bpfprogramresources.h"

namespace tob::ebpfpub {
struct BPFProgramResources::PrivateData final {
  StackMap::Ref event_stack_map;
  StackMap::Ref buffer_stack_map;
  EventMap::Ref event_map;
};

BPFProgramResources::BPFProgramResources(StackMap::Ref event_stack_map,
                                         StackMap::Ref buffer_stack_map,
                                         EventMap::Ref event_map)
    : d(new PrivateData) {
  d->event_stack_map = std::move(event_stack_map);
  d->buffer_stack_map = std::move(buffer_stack_map);
  d->event_map = std::move(event_map);
}

BPFProgramResources::BPFProgramResources() : d(new PrivateData) {}

BPFProgramResources::~BPFProgramResources() {}

StackMap &BPFProgramResources::eventStackMap() {
  return *d->event_stack_map.get();
}

StackMap &BPFProgramResources::bufferStackMap() {
  return *d->buffer_stack_map.get();
}

EventMap &BPFProgramResources::eventMap() { return *d->event_map.get(); }

BPFProgramResources::BPFProgramResources(BPFProgramResources &&other) {
  d = std::move(other.d);
  other.d = {};
}

BPFProgramResources &
BPFProgramResources::operator=(BPFProgramResources &&other) {
  if (this != &other) {
    d = std::move(other.d);
    other.d = {};
  }

  return *this;
}

// clang-format off
static_assert(
  std::is_move_constructible<BPFProgramResources>::value &&
  std::is_move_assignable<BPFProgramResources>::value,

  "BPFProgramResources must be movable"
);
// clang-format on
} // namespace tob::ebpfpub
