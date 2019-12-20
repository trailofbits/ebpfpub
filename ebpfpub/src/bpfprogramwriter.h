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

  llvm::Value *bpf_get_current_pid_tgid();
  llvm::Value *bpf_ktime_get_ns();
  llvm::Value *bpf_get_current_uid_gid();
  llvm::Value *bpf_get_smp_processor_id();

  llvm::Value *bpf_map_lookup_elem(int map_fd, llvm::Value *key,
                                   llvm::Type *type);

  void bpf_map_update_elem(int map_fd, llvm::Value *value, llvm::Value *key,
                           int flags);

  llvm::Value *bpf_probe_read_str(llvm::Value *dest, std::size_t size,
                                  llvm::Value *src);

  llvm::Value *bpf_probe_read(llvm::Value *dest, llvm::Value *size,
                              llvm::Value *src);

  SuccessOrStringError bpf_perf_event_output(int map_fd, std::uint64_t flags,
                                             llvm::Value *data_ptr,
                                             std::uint32_t data_size);

  BPFProgramWriter(const BPFProgramWriter &) = delete;
  BPFProgramWriter &operator=(const BPFProgramWriter &) = delete;

protected:
  BPFProgramWriter(llvm::Module &module, BufferStorage &buffer_storage,
                   const ebpf::TracepointEvent &enter_event,
                   const ebpf::TracepointEvent &exit_event);

private:
  llvm::Function *getPseudoInstrinsic();
  llvm::Value *bpf_pseudo_map_fd(int fd);

  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  StringErrorOr<llvm::Type *> importTracepointEventType(
      const ebpf::TracepointEvent::StructureField &structure_field);

  StringErrorOr<llvm::StructType *> importTracepointEventStructure(
      const ebpf::TracepointEvent::Structure &structure,
      const std::string &name);
};
} // namespace tob::ebpfpub
