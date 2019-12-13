/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "llvm_utils.h"

#include <llvm/ExecutionEngine/MCJIT.h>

namespace ebpfpub {
LLVMInitializer::LLVMInitializer() {
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT();
}

LLVMInitializer::~LLVMInitializer() { llvm::llvm_shutdown(); }

const LLVMInitializer kLLVMInitializer;

std::unique_ptr<llvm::Module> createLLVMModule(llvm::LLVMContext &llvm_context,
                                               const std::string &module_name) {

  auto llvm_module = std::make_unique<llvm::Module>(module_name, llvm_context);

  llvm_module->setTargetTriple("bpf-pc-linux");
  llvm_module->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");

  return llvm_module;
}

std::size_t getLLVMStructureSize(llvm::StructType *llvm_struct,
                                 llvm::Module *module) {

  llvm::DataLayout data_layout(module);

  auto size =
      static_cast<std::size_t>(data_layout.getTypeAllocSize(llvm_struct));

  return size;
}

StringErrorOr<llvm::Function *>
createSyscallEventFunction(llvm::Module *llvm_module, const std::string &name,
                           const std::string &parameter_type) {

  auto function_argument = llvm_module->getTypeByName(parameter_type);
  if (function_argument == nullptr) {
    return StringError::create(
        "The specified parameter type is not defined in the given module");
  }

  auto &llvm_context = llvm_module->getContext();

  auto function_type =
      llvm::FunctionType::get(llvm::Type::getInt64Ty(llvm_context),
                              {function_argument->getPointerTo()}, false);

  auto function_ptr = llvm::Function::Create(
      function_type, llvm::Function::ExternalLinkage, name, llvm_module);

  if (function_ptr == nullptr) {
    return StringError::create("Failed to create the syscall event function");
  }

  function_ptr->setSection(name + "_section");
  function_ptr->arg_begin()->setName("args");

  return function_ptr;
}
} // namespace ebpfpub
