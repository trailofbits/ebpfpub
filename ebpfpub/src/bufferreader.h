/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <memory>

#include <ebpfpub/ibufferreader.h>

namespace tob::ebpfpub {
class BufferReader final : public IBufferReader {
public:
  using Ref = std::unique_ptr<IBufferReader>;
  static StringErrorOr<Ref> create(const std::uint8_t *buffer,
                                   std::size_t buffer_size);

  virtual ~BufferReader() override;

  virtual std::size_t offset() const override;
  virtual void setOffset(std::size_t offset) override;
  virtual void skipBytes(std::size_t byte_count) override;

  virtual std::uint32_t u8() override;
  virtual std::uint32_t u16() override;
  virtual std::uint32_t u32() override;
  virtual std::uint64_t u64() override;

  virtual std::uint32_t peekU8(std::size_t offset) override;
  virtual std::uint32_t peekU16(std::size_t offset) override;
  virtual std::uint32_t peekU32(std::size_t offset) override;
  virtual std::uint64_t peekU64(std::size_t offset) override;

  virtual std::size_t bytesRead() const override;
  virtual std::size_t availableBytes() const override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BufferReader(const std::uint8_t *buffer, std::size_t buffer_size);
};
} // namespace tob::ebpfpub
