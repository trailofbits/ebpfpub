/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <sys/mman.h>

#include <ebpfpub/error.h>

namespace ebpfpub {
class UniqueMappedMemory final {
public:
  using Ref = std::unique_ptr<UniqueMappedMemory>;
  static StringErrorOr<Ref> create(void *address, std::size_t size,
                                   int protection, int flags, int fd,
                                   off_t off);

  std::byte *memory();

  ~UniqueMappedMemory();

  UniqueMappedMemory(const UniqueMappedMemory &) = delete;
  UniqueMappedMemory &operator=(const UniqueMappedMemory &) = delete;

  UniqueMappedMemory(UniqueMappedMemory &&other);
  UniqueMappedMemory &operator=(UniqueMappedMemory &&other);

protected:
  UniqueMappedMemory();
  UniqueMappedMemory(void *address, std::size_t size, int protection, int flags,
                     int fd, off_t off);

private:
  void *mapped_memory{nullptr};
  std::size_t mapped_memory_size{0U};

  void releaseMappedMemory();
};

// clang-format off
static_assert(
  std::is_move_constructible<UniqueMappedMemory>::value &&
  std::is_move_assignable<UniqueMappedMemory>::value,

  "UniqueMappedMemory must be movable"
);
// clang-format on
} // namespace ebpfpub
