#include "sectionmemorymanager.h"

namespace ebpfpub {
SectionMemoryManager::SectionMemoryManager(MemorySectionMap &section_list_)
    : section_list(section_list_) {}

SectionMemoryManager::~SectionMemoryManager() {}

std::uint8_t *
SectionMemoryManager::allocateCodeSection(uintptr_t size, unsigned alignment,
                                          unsigned section_id,
                                          llvm::StringRef section_name) {
  auto buffer = llvm::SectionMemoryManager::allocateDataSection(
      size, alignment, section_id, section_name, false);

  if (buffer == nullptr) {
    return nullptr;
  }

  RawMemorySection raw_section;
  raw_section.name = section_name;
  raw_section.alignment = alignment;
  raw_section.id = section_id;
  raw_section.code_section = true;
  raw_section.read_only = false;
  raw_section.size = size;
  raw_section.buffer = buffer;

  raw_section_list.push_back(std::move(raw_section));

  return buffer;
}

std::uint8_t *SectionMemoryManager::allocateDataSection(
    uintptr_t size, unsigned alignment, unsigned section_id,
    llvm::StringRef section_name, bool read_only) {
  static_cast<void>(read_only);

  auto buffer = llvm::SectionMemoryManager::allocateDataSection(
      size, alignment, section_id, section_name, false);

  if (buffer == nullptr) {
    return nullptr;
  }

  RawMemorySection raw_section;
  raw_section.name = section_name;
  raw_section.alignment = alignment;
  raw_section.id = section_id;
  raw_section.code_section = false;
  raw_section.read_only = read_only;
  raw_section.size = size;
  raw_section.buffer = buffer;

  raw_section_list.push_back(std::move(raw_section));

  return buffer;
}

bool SectionMemoryManager::finalizeMemory(std::string *error_messages) {
  section_list.clear();

  if (llvm::SectionMemoryManager::finalizeMemory(error_messages)) {
    raw_section_list.clear();
    return false;
  }

  for (const auto &raw_section : raw_section_list) {
    MemorySection section = {};
    section.type = raw_section.code_section ? MemorySection::Type::Code
                                            : MemorySection::Type::Data;

    section.name =
        std::string(raw_section.name.data(), raw_section.name.size());

    section.read_only = raw_section.read_only;
    section.alignment = static_cast<std::uint32_t>(raw_section.alignment);
    section.id = static_cast<std::uint32_t>(raw_section.id);

    section.data.resize(raw_section.size);
    std::memcpy(&section.data[0], raw_section.buffer, section.data.size());

    section_list.insert({section.name, std::move(section)});
  }

  raw_section_list.clear();
  return true;
}
} // namespace ebpfpub
