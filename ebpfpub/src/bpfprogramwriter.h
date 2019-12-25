/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "bpfprogramresources.h"

#include <memory>

#include <llvm/IR/IRBuilder.h>

#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/tracepointevent.h>

namespace tob::ebpfpub {
class BPFProgramWriter final {
public:
  using Ref = std::unique_ptr<BPFProgramWriter>;
  static StringErrorOr<Ref> create(llvm::Module &module,
                                   BufferStorage &buffer_storage,
                                   const ebpf::TracepointEvent &enter_event,
                                   const ebpf::TracepointEvent &exit_event);

  virtual ~BPFProgramWriter();

  llvm::IRBuilder<> &builder();
  ebpf::BPFSyscallInterface &bpfSyscallInterface();

  llvm::Module &module();
  llvm::LLVMContext &context();

  StringErrorOr<BPFProgramResources>
  initializeProgram(std::size_t event_map_size);

  StringErrorOr<llvm::Function *> getEnterFunction();
  StringErrorOr<llvm::Function *> getExitFunction();

  StringErrorOr<llvm::Type *> getEventEntryType();

  void setValue(const std::string &name, llvm::Value *value);
  void unsetValue(const std::string &name);
  void clearSavedValues();
  StringErrorOr<llvm::Value *> value(const std::string &name);

  StringErrorOr<llvm::Value *> generateBufferStorageIndex();

  StringErrorOr<llvm::Value *>
  markBufferStorageIndex(llvm::Value *buffer_storage_index);

  SuccessOrStringError captureString(llvm::Value *string_pointer);
  SuccessOrStringError captureBuffer(llvm::Value *buffer_pointer,
                                     llvm::Value *buffer_size);

  BPFProgramWriter(const BPFProgramWriter &) = delete;
  BPFProgramWriter &operator=(const BPFProgramWriter &) = delete;

protected:
  BPFProgramWriter(llvm::Module &module, BufferStorage &buffer_storage,
                   const ebpf::TracepointEvent &enter_event,
                   const ebpf::TracepointEvent &exit_event);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  StringErrorOr<llvm::Type *> importTracepointEventType(
      const ebpf::TracepointEvent::StructureField &structure_field);

  StringErrorOr<llvm::StructType *> importTracepointEventStructure(
      const ebpf::TracepointEvent::Structure &structure,
      const std::string &name);
};
} // namespace tob::ebpfpub
