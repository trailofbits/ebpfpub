/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "bufferstorage.h"

#include <memory>

#include <llvm/IR/IRBuilder.h>

#include <ebpfpub/ibpfprogramwriter.h>
#include <tob/ebpf/bpfmap.h>
#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/tracepointdescriptor.h>

namespace tob::ebpfpub {
class BPFProgramWriter final : public IBPFProgramWriter {
public:
  virtual ~BPFProgramWriter() override;

  virtual llvm::IRBuilder<> &builder() override;
  virtual ebpf::BPFSyscallInterface &bpfSyscallInterface() override;

  virtual llvm::Module &module() override;
  virtual llvm::LLVMContext &context() override;
  virtual ProgramType programType() const override;

  virtual StringErrorOr<llvm::Function *> getEnterFunction() override;
  virtual StringErrorOr<llvm::Function *> getExitFunction() override;
  virtual StringErrorOr<llvm::Type *> getEventEntryType() override;

  virtual StringErrorOr<llvm::Value *> value(const std::string &name) override;

  virtual SuccessOrStringError
  captureString(llvm::Value *string_pointer) override;
  virtual SuccessOrStringError captureBuffer(llvm::Value *buffer_pointer,
                                             llvm::Value *buffer_size) override;

  StringErrorOr<ProgramResources> initializeProgram(std::size_t event_map_size);

  void setValue(const std::string &name, llvm::Value *value);
  void unsetValue(const std::string &name);
  void clearSavedValues();

  StringErrorOr<llvm::Value *> generateBufferStorageIndex();

  StringErrorOr<llvm::Value *>
  markBufferStorageIndex(llvm::Value *buffer_storage_index);

protected:
  BPFProgramWriter(llvm::Module &module, IBufferStorage &buffer_storage,
                   const ebpf::Structure &enter_structure,
                   const ebpf::Structure &exit_structure,
                   ProgramType program_type);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  StringErrorOr<llvm::Type *>
  importTracepointDescriptorType(const ebpf::StructureField &structure_field);

  StringErrorOr<llvm::StructType *>
  importTracepointDescriptorStructure(const ebpf::Structure &structure,
                                      const std::string &name);

  friend class IBPFProgramWriter;
};
} // namespace tob::ebpfpub
