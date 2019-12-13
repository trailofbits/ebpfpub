/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "bpfoutput.h"

namespace ebpfpub {
struct BPFOutput::PrivateData final {
  UniqueMappedMemory::Ref memory;
  UniqueFd fd;
};

BPFOutput::BPFOutput(UniqueFd fd, UniqueMappedMemory::Ref memory)
    : d(new PrivateData) {
  d->fd = std::move(fd);
  d->memory = std::move(memory);
}

BPFOutput::~BPFOutput() {}

int BPFOutput::fd() const { return d->fd.get(); }

std::byte *BPFOutput::memory() const { return d->memory->memory(); }

BPFOutput::BPFOutput(BPFOutput &&other) {
  d = std::move(other.d);
  other.d = {};
}

BPFOutput &BPFOutput::operator=(BPFOutput &&other) {
  if (this != &other) {
    d = std::move(other.d);
    other.d = {};
  }

  return *this;
}
} // namespace ebpfpub
