#pragma once

#include <memory>
#include <unordered_map>

#include <ebpfpub/error.h>

namespace ebpfpub {
class IBufferStorage {
public:
  using Ref = std::shared_ptr<IBufferStorage>;
  static StringErrorOr<Ref> create(std::size_t buffer_size,
                                   std::size_t buffer_count);

  IBufferStorage() = default;
  virtual ~IBufferStorage() = default;

  virtual std::size_t memoryUsage() const = 0;
  virtual std::size_t bufferSize() const = 0;
  virtual std::size_t bufferCount() const = 0;

  IBufferStorage(const IBufferStorage &) = delete;
  IBufferStorage &operator=(const IBufferStorage &) = delete;
};
} // namespace ebpfpub
