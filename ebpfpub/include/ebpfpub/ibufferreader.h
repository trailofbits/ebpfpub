/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <memory>

#include <tob/error/error.h>

namespace tob::ebpfpub {
class IBufferReader {
public:
  using Ref = std::unique_ptr<IBufferReader>;
  static StringErrorOr<Ref> create(const std::uint8_t *buffer,
                                   std::size_t buffer_size);

  IBufferReader() = default;
  virtual ~IBufferReader() = default;

  virtual std::size_t offset() const = 0;
  virtual void setOffset(std::size_t offset) = 0;
  virtual void skipBytes(std::size_t byte_count) = 0;

  virtual std::uint32_t u8() = 0;
  virtual std::uint32_t u16() = 0;
  virtual std::uint32_t u32() = 0;
  virtual std::uint64_t u64() = 0;

  virtual std::uint32_t peekU8(std::size_t offset) = 0;
  virtual std::uint32_t peekU16(std::size_t offset) = 0;
  virtual std::uint32_t peekU32(std::size_t offset) = 0;
  virtual std::uint64_t peekU64(std::size_t offset) = 0;

  virtual std::size_t bytesRead() const = 0;
  virtual std::size_t availableBytes() const = 0;

  IBufferReader(const IBufferReader &) = delete;
  IBufferReader &operator=(const IBufferReader &) = delete;
};
} // namespace tob::ebpfpub
