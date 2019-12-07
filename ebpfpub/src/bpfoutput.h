#pragma once

#include "uniquefd.h"
#include "uniquemappedmemory.h"

#include <memory>

namespace ebpfpub {
class BPFOutput final {
public:
  BPFOutput(UniqueFd fd, UniqueMappedMemory::Ref memory);
  ~BPFOutput();

  int fd() const;
  std::byte *memory() const;

  BPFOutput(BPFOutput &&other);
  BPFOutput &operator=(BPFOutput &&other);

  BPFOutput(const BPFOutput &) = delete;
  BPFOutput &operator=(const BPFOutput &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

// clang-format off
static_assert(
  std::is_move_constructible<BPFOutput>::value &&
  std::is_move_assignable<BPFOutput>::value,

  "BPFOutput must be movable"
);
// clang-format on
} // namespace ebpfpub
