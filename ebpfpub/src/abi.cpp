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

#ifdef __aarch64__
// clang-format off
const std::unordered_map<std::string, std::uint32_t> kParameterNameToPtRegsIndex64 = {
  { "r0", 0U },
  { "r1", 1U },
  { "r2", 2U },
  { "r3", 3U },
  { "r4", 4U },
  { "r5", 5U },
  { "r6", 6U },
  { "r7", 7U },
  { "r8", 8U },
  { "r9", 9U },
  { "r10", 10U },
  { "r11", 11U },
  { "r12", 12U },
  { "r13", 13U },
  { "r14", 14U },
  { "r15", 15U },
  { "r16", 16U },
  { "r17", 17U },
  { "r18", 18U },
  { "r19", 19U },
  { "r20", 20U },
  { "r21", 21U },
  { "r22", 22U },
  { "r23", 23U },
  { "r24", 24U },
  { "r25", 25U },
  { "r26", 26U },
  { "r27", 27U },
  { "r28", 28U },
  { "r29", 29U },
  { "r30", 30U },
  { "sp", 31U },
  { "pc", 32U },
  { "pstate", 33U },
};
// clang-format on

// clang-format off
const std::unordered_map<std::uint32_t, std::string> kSyscallParameterIndexToRegisterName64 = {
  { 0U, "r0" },
  { 1U, "r1" },
  { 2U, "r2" },
  { 3U, "r3" },
  { 4U, "r4" },
  { 5U, "r5" }
};
// clang-format on

const std::string kRetSyscallRegister{"r14"};

#elif __amd64__
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
const std::unordered_map<std::uint32_t, std::string> kSyscallParameterIndexToRegisterName64 = {
  { 0U, "rdi" },
  { 1U, "rsi" },
  { 2U, "rdx" },
  { 3U, "r10" },
  { 4U, "r8" },
  { 5U, "r9" }
};
// clang-format on

const std::string kRetSyscallRegister{"rax"};

#else
#error Unsupported architecture
#endif
} // namespace

StringErrorOr<llvm::Value *>
getPtRegsParameterFromName(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                           const std::string &name, llvm::Type *type) {

  auto parameter_it = kParameterNameToPtRegsIndex64.find(name);
  if (parameter_it == kParameterNameToPtRegsIndex64.end()) {
    return StringError::create(
        "Invalid register name specified for pt_regs structure: " + name);
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

StringErrorOr<std::uint32_t>
translateParameterNumberToPtregsIndex(std::uint32_t index) {
  auto reg_name_it = kSyscallParameterIndexToRegisterName64.find(index);
  if (reg_name_it == kSyscallParameterIndexToRegisterName64.end()) {
    return StringError::create("Invalid parameter number");
  }

  const auto &reg_name = reg_name_it->second;

  auto param_index_it = kParameterNameToPtRegsIndex64.find(reg_name);
  if (param_index_it == kParameterNameToPtRegsIndex64.end()) {
    return StringError::create("Invalid register name");
  }

  auto ptregs_index = static_cast<std::uint32_t>(param_index_it->second);
  return ptregs_index;
}

StringErrorOr<llvm::Value *>
getReturnValuePtregsEntry(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                          llvm::Type *type) {
  return getPtRegsParameterFromName(builder, pt_regs, kRetSyscallRegister,
                                    type);
}
} // namespace tob::ebpfpub
