/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <tob/error/error.h>

namespace tob::ebpfpub {
class BufferReader final {
public:
  using Ref = std::unique_ptr<BufferReader>;
  static StringErrorOr<Ref> create();

  ~BufferReader();

  void reset(const std::vector<std::uint8_t> &buffer);

  std::size_t offset() const;
  void setOffset(std::size_t offset);
  void skipBytes(std::size_t byte_count);

  std::uint32_t u8();
  std::uint32_t u16();
  std::uint32_t u32();
  std::uint64_t u64();

  std::uint32_t peekU8(std::size_t offset);
  std::uint32_t peekU16(std::size_t offset);
  std::uint32_t peekU32(std::size_t offset);
  std::uint64_t peekU64(std::size_t offset);

  std::size_t bytesRead() const;
  std::size_t availableBytes() const;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BufferReader();
};
} // namespace tob::ebpfpub
