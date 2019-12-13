/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <unordered_map>

#include <llvm/ExecutionEngine/SectionMemoryManager.h>

namespace ebpfpub {
struct MemorySection final {
  enum class Type { Code, Data };

  Type type{Type::Code};
  bool read_only{false};

  std::string name;

  std::uint32_t alignment{};
  std::uint32_t id{};

  std::vector<std::uint8_t> data;
};

using MemorySectionMap = std::unordered_map<std::string, MemorySection>;

class SectionMemoryManager final : public llvm::SectionMemoryManager {
  struct RawMemorySection final {
    llvm::StringRef name{};

    unsigned alignment{};
    unsigned id{};
    bool code_section{false};
    bool read_only{false};

    uintptr_t size{};
    const std::uint8_t *buffer{nullptr};
  };

  std::vector<RawMemorySection> raw_section_list;
  MemorySectionMap &section_list;

public:
  SectionMemoryManager(MemorySectionMap &section_list_);
  virtual ~SectionMemoryManager();

  virtual uint8_t *allocateCodeSection(uintptr_t size, unsigned alignment,
                                       unsigned section_id,
                                       llvm::StringRef section_name) override;

  uint8_t *allocateDataSection(uintptr_t size, unsigned alignment,
                               unsigned section_id,
                               llvm::StringRef section_name,
                               bool read_only) override;

  virtual bool finalizeMemory(std::string *error_messages = nullptr) override;
};
} // namespace ebpfpub
