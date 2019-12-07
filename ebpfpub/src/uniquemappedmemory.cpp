#include "uniquemappedmemory.h"

namespace ebpfpub {
StringErrorOr<UniqueMappedMemory::Ref>
UniqueMappedMemory::create(void *address, std::size_t size, int protection,
                           int flags, int fd, off_t off) {
  try {
    return Ref(
        new UniqueMappedMemory(address, size, protection, flags, fd, off));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

std::byte *UniqueMappedMemory::memory() {
  return static_cast<std::byte *>(mapped_memory);
}

UniqueMappedMemory::UniqueMappedMemory() {}

UniqueMappedMemory::~UniqueMappedMemory() { releaseMappedMemory(); }

UniqueMappedMemory::UniqueMappedMemory(UniqueMappedMemory &&other) {
  mapped_memory = other.mapped_memory;
  mapped_memory_size = other.mapped_memory_size;

  other.mapped_memory = nullptr;
  other.mapped_memory_size = 0U;
}

UniqueMappedMemory &UniqueMappedMemory::operator=(UniqueMappedMemory &&other) {
  if (this != &other) {
    releaseMappedMemory();

    mapped_memory = other.mapped_memory;
    mapped_memory_size = other.mapped_memory_size;

    other.mapped_memory = nullptr;
    other.mapped_memory_size = 0U;
  }

  return *this;
}

void UniqueMappedMemory::releaseMappedMemory() {
  if (mapped_memory == nullptr) {
    return;
  }

  munmap(mapped_memory, mapped_memory_size);

  mapped_memory = nullptr;
  mapped_memory_size = 0U;
}

UniqueMappedMemory::UniqueMappedMemory(void *address, std::size_t size,
                                       int protection, int flags, int fd,
                                       off_t off) {
  mapped_memory_size = size;
  mapped_memory = mmap(address, size, protection, flags, fd, off);
  if (mapped_memory == MAP_FAILED) {
    throw StringError::create("Failed to create the memory mapping");
  }
}
} // namespace ebpfpub
