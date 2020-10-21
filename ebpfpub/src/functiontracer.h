/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "bufferreader.h"

#include <ebpfpub/ifunctiontracer.h>

#include <tob/ebpf/bpfsyscallinterface.h>
#include <tob/ebpf/iperfevent.h>

namespace tob::ebpfpub {
class FunctionTracer final : public IFunctionTracer {
public:
  using Ref = std::unique_ptr<FunctionTracer>;

  struct ParameterListIndexEntry final {
    std::size_t param_index{0U};
    std::size_t source_index{0U};
    std::optional<std::size_t> destination_index_in_opt;
    std::optional<std::size_t> destination_index_out_opt;
  };

  using ParameterListIndex = std::vector<ParameterListIndexEntry>;

  ~FunctionTracer();

  virtual const std::string &name() const override;
  virtual std::uint64_t eventIdentifier() const override;

  virtual std::string ir() const override;

  StringErrorOr<EventList> parseEventData(BufferReader &buffer_reader) const;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  FunctionTracer(const std::string &name, const ParameterList &parameter_list,
                 std::size_t event_map_size, IBufferStorage &buffer_storage,
                 ebpf::PerfEventArray &perf_event_array,
                 ebpf::IPerfEvent::Ref enter_event,
                 ebpf::IPerfEvent::Ref exit_event,
                 OptionalPidList excluded_processes);

  friend class IFunctionTracer;

public:
  using StackAllocationList = std::unordered_map<std::string, llvm::Value *>;
  using VariableList = std::unordered_map<std::string, llvm::Value *>;
  using EventMap = ebpf::BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;

  using EventScratchSpace =
      ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

  static StringErrorOr<ParameterListIndex> createParameterListIndex(
      bool is_tracepoint,
      const FunctionTracer::ParameterList &valid_param_list);

  static StringErrorOr<llvm::Value *>
  getStackAllocation(const StackAllocationList &allocation_list,
                     const std::string &name);

  static SuccessOrStringError
  allocateStackSpace(StackAllocationList &allocation_list,
                     const std::string &name, llvm::IRBuilder<> &builder,
                     llvm::Type *allocation_type);

  static StringErrorOr<llvm::Value *>
  getVariable(const VariableList &variable_list, const std::string &name);

  static SuccessOrStringError saveVariable(VariableList &variable_list,
                                           const std::string &name,
                                           llvm::Value *value);

  static StringErrorOr<llvm::Value *>
  generateBufferStorageIndex(llvm::IRBuilder<> &builder,
                             const VariableList &variable_list,
                             IBufferStorage &buffer_storage);

  static llvm::Value *
  tagBufferStorageIndex(ebpf::BPFSyscallInterface &bpf_syscall_interface,
                        llvm::IRBuilder<> &builder,
                        llvm::Value *buffer_storage_index);

  static SuccessOrStringError
  validateParameterList(const ParameterList &parameter_list,
                        IBufferStorage &buffer_storage);

  static llvm::Type *llvmTypeForMemoryPointer(llvm::Module &module);

  static SuccessOrStringError createEventHeaderType(llvm::Module &module);

  static SuccessOrStringError
  createEventDataType(llvm::Module &module,
                      const ParameterList &valid_param_list);

  static SuccessOrStringError createEventType(llvm::Module &module);

  static StringErrorOr<EventMap::Ref>
  createEventMap(llvm::Module &module, std::size_t event_map_size);

  static StringErrorOr<EventScratchSpace::Ref>
  createEventScratchSpace(llvm::Module &module);

  static SuccessOrStringError
  createEnterFunctionArgumentType(llvm::Module &module,
                                  ebpf::IPerfEvent &enter_event,
                                  const ParameterList &parameter_list);

  static SuccessOrStringError
  createExitFunctionArgumentType(llvm::Module &module,
                                 ebpf::IPerfEvent &exit_event);

  static StringErrorOr<llvm::Value *>
  getMapEntry(int fd, llvm::IRBuilder<> &builder,
              ebpf::BPFSyscallInterface &bpf_syscall_interface,
              const StackAllocationList &allocation_list,
              llvm::Value *map_index_value, llvm::Type *map_entry_type,
              const std::string &label);

  static SuccessOrStringError createEnterFunction(
      llvm::Module &module, EventMap &event_map,
      EventScratchSpace &event_scratch_space, ebpf::IPerfEvent &enter_event,
      const ParameterList &parameter_list,
      const ParameterListIndex &param_list_index,
      IBufferStorage &buffer_storage, OptionalPidList excluded_processes);

  static SuccessOrStringError
  generateEventHeader(llvm::IRBuilder<> &builder, ebpf::IPerfEvent &enter_event,
                      ebpf::BPFSyscallInterface &bpf_syscall_interface,
                      llvm::Value *event_object);

  static SuccessOrStringError generateEnterEventData(
      llvm::IRBuilder<> &builder, ebpf::IPerfEvent &enter_event,
      ebpf::BPFSyscallInterface &bpf_syscall_interface,
      llvm::Value *event_object, const ParameterList &parameter_list,
      const ParameterListIndex &param_list_index,
      IBufferStorage &buffer_storage,
      const StackAllocationList &allocation_list,
      const VariableList &variable_list);

  static SuccessOrStringError createExitFunction(
      llvm::Module &module, EventMap &event_map, ebpf::IPerfEvent &exit_event,
      const ParameterList &parameter_list,
      const ParameterListIndex &param_list_index,
      IBufferStorage &buffer_storage, ebpf::PerfEventArray &perf_event_array,
      bool skip_exit_code);

  static SuccessOrStringError generateExitEventData(
      llvm::IRBuilder<> &builder, ebpf::IPerfEvent &exit_event,
      ebpf::BPFSyscallInterface &bpf_syscall_interface,
      llvm::Value *event_object, const ParameterList &parameter_list,
      const ParameterListIndex &param_list_index,
      IBufferStorage &buffer_storage,
      const StackAllocationList &allocation_list,
      const VariableList &variable_list);

  static void
  captureIntegerByPointer(llvm::IRBuilder<> &builder,
                          ebpf::BPFSyscallInterface &bpf_syscall_interface,
                          const Parameter &param, llvm::Value *event_data_field,
                          llvm::Value *probe_error_flag);

  static StringErrorOr<EventList>
  parseEventData(BufferReader &buffer_reader, std::uint32_t event_object_size,
                 std::uint64_t event_object_identifier,
                 const std::string &event_name,
                 const ParameterList &parameter_list,
                 const ParameterListIndex &param_list_index,
                 IBufferStorage &buffer_storage);

  static SuccessOrStringError captureString(
      llvm::IRBuilder<> &builder,
      ebpf::BPFSyscallInterface &bpf_syscall_interface,
      IBufferStorage &buffer_storage,
      const StackAllocationList &allocation_list,
      const VariableList &variable_list, llvm::Value *event_data_field,
      const std::string &parameter_name, llvm::Value *probe_error_flag);

  static SuccessOrStringError
  captureBuffer(llvm::IRBuilder<> &builder,
                ebpf::BPFSyscallInterface &bpf_syscall_interface,
                IBufferStorage &buffer_storage,
                const StackAllocationList &allocation_list,
                const VariableList &variable_list,
                llvm::Value *event_data_field,
                const std::string &parameter_name,
                llvm::Value *probe_error_flag, llvm::Value *buffer_size);

  static SuccessOrStringError
  captureArgv(llvm::IRBuilder<> &builder,
              ebpf::BPFSyscallInterface &bpf_syscall_interface,
              IBufferStorage &buffer_storage,
              const StackAllocationList &allocation_list,
              const VariableList &variable_list, llvm::Value *event_data_field,
              const std::string &parameter_name, llvm::Value *probe_error_flag,
              std::size_t argv_size);
};
} // namespace tob::ebpfpub
