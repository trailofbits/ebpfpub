#pragma once

#include <cstdint>
#include <memory>

namespace ebpfpub {
class BufferReader final {
public:
  BufferReader(const std::uint8_t *buffer, std::size_t buffer_size);
  ~BufferReader();

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

  BufferReader(const BufferReader &) = delete;
  BufferReader &operator=(const BufferReader &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace ebpfpub
