/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "abi.h"

#include <unordered_map>

namespace tob::ebpfpub {
namespace {
// clang-format off
const std::unordered_map<std::string, std::uint32_t> kParameterNameToPtRegsIndex64 = {
  { "r15", 0U },
  { "r14", 1U },
  { "r13", 2U },
  { "r12", 3U },
  { "rbp", 4U },
  { "rbx", 5U },
  { "r11", 6U },
  { "r10", 7U },
  { "r9", 8U },
  { "r8", 9U },
  { "rax", 10U },
  { "rcx", 11U },
  { "rdx", 12U },
  { "rsi", 13U },
  { "rdi", 14U },
  { "orig_rax", 15U },
  { "rip", 16U },
  { "cs", 17U },
  { "eflags", 18U },
  { "rsp", 19U },
  { "ss", 20U }
};
// clang-format on

// clang-format off
std::unordered_map<std::uint32_t, std::string> kSyscallParameterIndexToRegisterName64 = {
  { 0U, "rdi" },
  { 1U, "rsi" },
  { 2U, "rdx" },
  { 3U, "r10" },
  { 4U, "r8" },
  { 5U, "r9" }
};
// clang-format on
} // namespace

StringErrorOr<llvm::Value *>
getPtRegsParameterFromName(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                           const std::string &name, llvm::Type *type) {

  auto parameter_it = kParameterNameToPtRegsIndex64.find(name);
  if (parameter_it == kParameterNameToPtRegsIndex64.end()) {
    return StringError::create(
        "Invalid register name specified for pt_regs structure");
  }

  auto field_index = parameter_it->second;

  auto value = builder.CreateGEP(
      pt_regs, {builder.getInt32(0), builder.getInt32(field_index)});

  if (type != nullptr && value->getType() != type) {
    value = builder.CreateCast(llvm::Instruction::BitCast, value, type);
  }

  return value;
}

StringErrorOr<llvm::Value *>
getRegisterForParameterIndex(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                             std::uint32_t index, llvm::Type *type) {

  if (index > 6) {
    return StringError::create("Invalid parameter index specified");
  }

  const auto &register_name = kSyscallParameterIndexToRegisterName64.at(index);
  return getPtRegsParameterFromName(builder, pt_regs, register_name, type);
}
} // namespace tob::ebpfpub
