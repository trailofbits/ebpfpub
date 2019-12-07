#include "bufferreader.h"

#include <cstring>
#include <iostream>

namespace ebpfpub {
namespace {
template <typename Type>
Type readType(const std::uint8_t *&buffer, std::size_t &buffer_size,
              std::size_t &bytes_read) {
  Type output{};
  if (bytes_read + sizeof(output) > buffer_size) {
    std::cout << bytes_read << " + " << sizeof(output) << " >= " << buffer_size
              << std::endl;
    throw std::runtime_error("Not enough bytes");
  }

  std::memcpy(&output, buffer + bytes_read, sizeof(output));
  bytes_read += sizeof(output);

  return output;
}
} // namespace

struct BufferReader::PrivateData final {
  const std::uint8_t *buffer{nullptr};
  std::size_t buffer_size{0U};

  std::size_t bytes_read{0U};
};

BufferReader::BufferReader(const std::uint8_t *buffer, std::size_t buffer_size)
    : d(new PrivateData) {
  d->buffer = buffer;
  d->buffer_size = buffer_size;
}

BufferReader::~BufferReader() {}

std::size_t BufferReader::offset() const { return d->bytes_read; }

void BufferReader::setOffset(std::size_t offset) { d->bytes_read = offset; }

void BufferReader::skipBytes(std::size_t byte_count) {
  d->bytes_read += byte_count;
}

std::uint32_t BufferReader::u8() {
  return readType<std::uint8_t>(d->buffer, d->buffer_size, d->bytes_read);
}

std::uint32_t BufferReader::u16() {
  return readType<std::uint16_t>(d->buffer, d->buffer_size, d->bytes_read);
}

std::uint32_t BufferReader::u32() {
  return readType<std::uint32_t>(d->buffer, d->buffer_size, d->bytes_read);
}

std::uint64_t BufferReader::u64() {
  return readType<std::uint64_t>(d->buffer, d->buffer_size, d->bytes_read);
}

std::uint32_t BufferReader::peekU8(std::size_t offset) {
  offset += d->bytes_read;
  return readType<std::uint8_t>(d->buffer, d->buffer_size, offset);
}

std::uint32_t BufferReader::peekU16(std::size_t offset) {
  offset += d->bytes_read;
  return readType<std::uint16_t>(d->buffer, d->buffer_size, offset);
}

std::uint32_t BufferReader::peekU32(std::size_t offset) {
  offset += d->bytes_read;
  return readType<std::uint32_t>(d->buffer, d->buffer_size, offset);
}

std::uint64_t BufferReader::peekU64(std::size_t offset) {
  offset += d->bytes_read;
  return readType<std::uint64_t>(d->buffer, d->buffer_size, offset);
}

std::size_t BufferReader::bytesRead() const { return d->bytes_read; }

std::size_t BufferReader::availableBytes() const {
  return d->buffer_size - d->bytes_read;
}
} // namespace ebpfpub
