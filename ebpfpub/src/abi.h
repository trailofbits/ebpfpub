/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <string>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>

#include <tob/error/error.h>

namespace tob::ebpfpub {
StringErrorOr<llvm::Value *>
getPtRegsParameterFromName(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                           const std::string &name, llvm::Type *type = nullptr);

StringErrorOr<llvm::Value *>
getRegisterForParameterIndex(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                             std::uint32_t index, llvm::Type *type = nullptr);

StringErrorOr<std::uint32_t>
translateParameterNumberToPtregsIndex(std::uint32_t index);

StringErrorOr<llvm::Value *>
getReturnValuePtregsEntry(llvm::IRBuilder<> &builder, llvm::Value *pt_regs,
                          llvm::Type *type = nullptr);
} // namespace tob::ebpfpub
