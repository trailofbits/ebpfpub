/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <llvm/IR/IRBuilder.h>

#include <ebpfpub/ibufferstorage.h>
#include <tob/ebpf/bpfmap.h>
#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/tracepointdescriptor.h>

namespace tob::ebpfpub {
class IBPFProgramWriter {
public:
  using Ref = std::unique_ptr<IBPFProgramWriter>;
  using EventMap = ebpf::BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;
  using StackMap = ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

  struct ProgramResources final {
    StackMap::Ref event_stack_map;
    StackMap::Ref buffer_stack_map;
    EventMap::Ref event_map;
  };

  enum class ProgramType { Tracepoint, Kprobe, Uprobe };

  static StringErrorOr<Ref> create(llvm::Module &module,
                                   IBufferStorage &buffer_storage,
                                   const ebpf::Structure &enter_structure,
                                   const ebpf::Structure &exit_structure,
                                   ProgramType program_type);

  IBPFProgramWriter() = default;
  virtual ~IBPFProgramWriter() = default;

  virtual llvm::IRBuilder<> &builder() = 0;
  virtual ebpf::BPFSyscallInterface &bpfSyscallInterface() = 0;

  virtual llvm::Module &module() = 0;
  virtual llvm::LLVMContext &context() = 0;
  virtual ProgramType programType() const = 0;

  virtual StringErrorOr<llvm::Function *> getEnterFunction() = 0;
  virtual StringErrorOr<llvm::Function *> getExitFunction() = 0;
  virtual StringErrorOr<llvm::Type *> getEventEntryType() = 0;

  virtual StringErrorOr<llvm::Value *> value(const std::string &name) = 0;

  virtual SuccessOrStringError captureString(llvm::Value *string_pointer) = 0;
  virtual SuccessOrStringError captureBuffer(llvm::Value *buffer_pointer,
                                             llvm::Value *buffer_size) = 0;

  IBPFProgramWriter(const IBPFProgramWriter &) = delete;
  IBPFProgramWriter &operator=(const IBPFProgramWriter &) = delete;
};
} // namespace tob::ebpfpub
