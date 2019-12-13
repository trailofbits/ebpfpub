/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>

#include <ebpfpub/error.h>

namespace ebpfpub {
class LLVMInitializer final {
public:
  LLVMInitializer();
  ~LLVMInitializer();
};

extern const LLVMInitializer kLLVMInitializer;

std::unique_ptr<llvm::Module> createLLVMModule(llvm::LLVMContext &llvm_context,
                                               const std::string &module_name);

std::size_t getLLVMStructureSize(llvm::StructType *llvm_struct,
                                 llvm::Module *module);

StringErrorOr<llvm::Function *>
createSyscallEventFunction(llvm::Module *llvm_module, const std::string &name,
                           const std::string &parameter_type);
} // namespace ebpfpub
