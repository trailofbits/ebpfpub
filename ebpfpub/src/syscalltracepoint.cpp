/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "syscalltracepoint.h"
#include "syscallserializerfactory.h"

#include <fstream>
#include <iostream>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>

#include <tob/ebpf/bpfmap.h>
#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/llvm_utils.h>
#include <tob/ebpf/tracepointevent.h>

namespace tob::ebpfpub {
namespace {
using EventMap = ebpf::BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;
using StackMap = ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

const std::string kSyscallsEventCategory{"syscalls"};
const std::string kEnterEventNamePrefix{"sys_enter_"};
const std::string kExitEventNamePrefix{"sys_exit_"};

const std::string kLLVMModuleName{"SyscallModule"};
} // namespace

struct SyscallTracepoint::PrivateData final {
  PrivateData(IBufferStorage &buffer_storage_,
              ebpf::PerfEventArray &perf_event_array_)
      : buffer_storage(buffer_storage_), perf_event_array(perf_event_array_) {}

  std::string syscall_name;

  IBufferStorage &buffer_storage;
  ebpf::PerfEventArray &perf_event_array;

  ebpf::TracepointEvent::Ref enter_event;
  ebpf::TracepointEvent::Ref exit_event;

  llvm::LLVMContext llvm_context;
  std::unique_ptr<llvm::Module> llvm_module;

  BPFProgramResources program_resources;
  ISyscallSerializer::Ref syscall_serializer;

  utils::UniqueFd enter_event_fd;
  utils::UniqueFd enter_program_fd;

  utils::UniqueFd exit_event_fd;
  utils::UniqueFd exit_program_fd;
};

SyscallTracepoint::~SyscallTracepoint() { stop(); }

const std::string &SyscallTracepoint::syscallName() const {
  return d->syscall_name;
}

const std::string &SyscallTracepoint::serializerName() const {
  return d->syscall_serializer->name();
}

StringErrorOr<std::string> SyscallTracepoint::generateIR() const {
  std::string buffer;

  llvm::raw_string_ostream stream(buffer);
  d->llvm_module->print(stream, nullptr, false, true);

  if (buffer.empty()) {
    return StringError::create("Failed to generate the IR");
  }

  return buffer;
}

std::uint32_t SyscallTracepoint::eventIdentifier() const {
  return d->enter_event->eventIdentifier();
}

StringErrorOr<SyscallTracepoint::EventList>
SyscallTracepoint::parseEvents(BufferReader &buffer_reader) const {
  EventList event_list;

  auto &buffer_storage_impl = static_cast<BufferStorage &>(d->buffer_storage);

  for (;;) {
    if (buffer_reader.availableBytes() < 8U) {
      return StringError::create("Not enough bytes to read the event");
    }

    auto entry_size = buffer_reader.peekU32(0U);
    auto event_identifier = buffer_reader.peekU32(4U);

    if (event_identifier != eventIdentifier()) {
      break;
    }

    entry_size -= sizeof(entry_size) + sizeof(event_identifier);

    if (entry_size > buffer_reader.availableBytes()) {
      return StringError::create("Not enough bytes to read the event");
    }

    buffer_reader.skipBytes(8U);

    Event event = {};
    event.syscall_name = d->syscall_name;

    event.header.timestamp = buffer_reader.u64();
    event.header.parent_process_id = 0U;
    event.header.thread_id = static_cast<pid_t>(buffer_reader.u32());
    event.header.process_id = static_cast<pid_t>(buffer_reader.u32());
    event.header.user_id = buffer_reader.u32();
    event.header.group_id = buffer_reader.u32();
    event.header.exit_code = buffer_reader.u64();
    event.header.probe_error = (buffer_reader.u64() != 0U);

    auto success_exp = d->syscall_serializer->parseEvents(event, buffer_reader,
                                                          buffer_storage_impl);
    if (success_exp.failed()) {
      return success_exp.error();
    }

    event_list.push_back(std::move(event));

    if (buffer_reader.availableBytes() == 0U) {
      break;
    }
  }

  if (event_list.empty()) {
    return StringError::create("Failed to read any event");
  }

  return event_list;
}

SuccessOrStringError SyscallTracepoint::start() {
  // Compile the module; we'll obtain one program for the enter event, and
  // another one for the exit event
  auto &module = *d->llvm_module.get();

  auto program_map_exp = ebpf::compileModule(module);
  if (!program_map_exp.succeeded()) {
    return program_map_exp.error();
  }

  auto program_map = program_map_exp.takeValue();

  auto enter_program_it = program_map.find("on_syscall_enter_section");

  if (enter_program_it == program_map.end()) {
    return StringError::create("Failed to compile the enter program");
  }

  auto &enter_program = enter_program_it->second;

  auto exit_program_it = program_map.find("on_syscall_exit_section");

  if (exit_program_it == program_map.end()) {
    return StringError::create("Failed to compile the exit program");
  }

  auto &exit_program = exit_program_it->second;

  // Start both tracepoints
  auto tracepoints_status = enableTracepoints();
  if (tracepoints_status.failed()) {
    return tracepoints_status.error();
  }

  // Load the enter program
  auto enter_event_exp =
      ebpf::createTracepointEvent(d->enter_event->eventIdentifier(), -1);

  if (!enter_event_exp.succeeded()) {
    return enter_event_exp.error();
  }

  d->enter_event_fd = enter_event_exp.takeValue();

  auto program_exp = ebpf::loadProgram(enter_program, d->enter_event_fd.get(),
                                       BPF_PROG_TYPE_TRACEPOINT);

  if (!program_exp.succeeded()) {
    auto load_error = "The 'enter' program could not be loaded: " +
                      program_exp.error().message();

    return StringError::create(load_error);
  }

  d->enter_program_fd = program_exp.takeValue();

  // Load the exit program
  auto exit_event_exp =
      ebpf::createTracepointEvent(d->exit_event->eventIdentifier(), -1);

  if (!exit_event_exp.succeeded()) {
    return exit_event_exp.error();
  }

  d->exit_event_fd = exit_event_exp.takeValue();

  program_exp = ebpf::loadProgram(exit_program, d->exit_event_fd.get(),
                                  BPF_PROG_TYPE_TRACEPOINT);

  if (!program_exp.succeeded()) {
    auto load_error = "The 'exit' program could not be loaded: " +
                      program_exp.error().message();

    return StringError::create(load_error);
  }

  d->exit_program_fd = program_exp.takeValue();
  return {};
}

void SyscallTracepoint::stop() {
  disableTracepoints();

  ebpf::closeEvent(d->enter_event_fd);
  d->enter_program_fd.reset();

  ebpf::closeEvent(d->exit_event_fd);
  d->exit_program_fd.reset();
}

SyscallTracepoint::SyscallTracepoint(const std::string &syscall_name,
                                     IBufferStorage &buffer_storage,
                                     ebpf::PerfEventArray &perf_event_array,
                                     std::size_t event_map_size)
    : d(new PrivateData(buffer_storage, perf_event_array)) {

  static auto serializers_initialized_exp = initializeSerializerFactory();

  if (serializers_initialized_exp.failed()) {
    throw serializers_initialized_exp.error();
  }

  d->syscall_name = syscall_name;

  // Open the tracepoint events
  auto event_exp = ebpf::TracepointEvent::create(
      kSyscallsEventCategory, kEnterEventNamePrefix + d->syscall_name);

  if (!event_exp.succeeded()) {
    throw event_exp.error();
  }

  d->enter_event = event_exp.takeValue();

  event_exp = ebpf::TracepointEvent::create(
      kSyscallsEventCategory, kExitEventNamePrefix + d->syscall_name);

  if (!event_exp.succeeded()) {
    throw event_exp.error();
  }

  d->exit_event = event_exp.takeValue();

  // Initialize the LLVM module
  d->llvm_module = ebpf::createLLVMModule(d->llvm_context, kLLVMModuleName);
  if (!d->llvm_module) {
    throw StringError::create("Failed to generate the LLVM BPF module");
  }

  // Create the BPF writer helper
  auto &buffer_storage_impl = static_cast<BufferStorage &>(d->buffer_storage);

  auto bpf_program_writer_exp =
      BPFProgramWriter::create(*d->llvm_module.get(), buffer_storage_impl,
                               *d->enter_event.get(), *d->exit_event.get());

  if (!bpf_program_writer_exp.succeeded()) {
    throw bpf_program_writer_exp.error();
  }

  auto bpf_program_writer = bpf_program_writer_exp.takeValue();

  // Initialize the types and the internal maps
  auto program_resources_exp =
      bpf_program_writer->initializeProgram(event_map_size);

  if (!program_resources_exp.succeeded()) {
    throw program_resources_exp.error();
  }

  d->program_resources = program_resources_exp.takeValue();

  // Generate the common enter function
  auto success_exp = generateEnterFunction(*bpf_program_writer.get());
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  bpf_program_writer->clearSavedValues();

  // Initialize the exit function
  success_exp = initializeExitFunction(*bpf_program_writer.get());
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Get a suitable serializer to complete the exit function
  auto serializer_ref_exp = createSerializer(syscall_name);
  if (!serializer_ref_exp.succeeded()) {
    throw serializer_ref_exp.error();
  }

  d->syscall_serializer = serializer_ref_exp.takeValue();

  success_exp = d->syscall_serializer->generate(*d->enter_event.get(),
                                                *bpf_program_writer.get());
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Finalize the exit function
  success_exp = finalizeExitFunction(*bpf_program_writer.get());
  if (success_exp.failed()) {
    throw success_exp.error();
  }
}

SuccessOrStringError
SyscallTracepoint::generateEnterFunction(BPFProgramWriter &bpf_prog_writer) {
  auto &builder = bpf_prog_writer.builder();
  auto &context = bpf_prog_writer.context();
  auto &module = bpf_prog_writer.module();

  // Create the function
  auto event_function_exp = bpf_prog_writer.getEnterFunction();

  if (!event_function_exp.succeeded()) {
    return event_function_exp.error();
  }

  auto enter_event_function = event_function_exp.takeValue();

  // Generate the entry basic block
  auto entry_bb =
      llvm::BasicBlock::Create(context, "entry", enter_event_function);

  builder.SetInsertPoint(entry_bb);

  // Pre-allocate all buffers
  auto event_entry_key = builder.CreateAlloca(builder.getInt64Ty());
  auto stack_space_key = builder.CreateAlloca(builder.getInt64Ty());

  // Automatically filter out this event if it's coming from our PID
  auto process_id = builder.getInt64(static_cast<std::uint64_t>(getpid()));

  auto current_pid_tgid = bpf_prog_writer.bpf_get_current_pid_tgid();

  auto current_tgid =
      builder.CreateBinOp(llvm::Instruction::And, current_pid_tgid,
                          builder.getInt64(0x00000000FFFFFFFFU));

  auto check_pid_condition = builder.CreateICmpEQ(process_id, current_tgid);

  auto ignore_event_bb =
      llvm::BasicBlock::Create(context, "ignore_event", enter_event_function);

  auto get_event_stack_map_entry_bb = llvm::BasicBlock::Create(
      context, "get_event_stack_map_entry", enter_event_function);

  builder.CreateCondBr(check_pid_condition, ignore_event_bb,
                       get_event_stack_map_entry_bb);

  builder.SetInsertPoint(ignore_event_bb);
  builder.CreateRet(builder.getInt64(0));

  // Get the first entry in the event stack map and use it as temporary storage
  builder.SetInsertPoint(get_event_stack_map_entry_bb);
  builder.CreateStore(builder.getInt64(0), stack_space_key);

  auto event_entry_type_exp = bpf_prog_writer.getEventEntryType();
  if (!event_entry_type_exp.succeeded()) {
    return event_entry_type_exp.error();
  }

  auto event_entry_type = event_entry_type_exp.takeValue();
  auto event_entry_type_ptr = event_entry_type->getPointerTo();

  auto event_stack_ptr = bpf_prog_writer.bpf_map_lookup_elem(
      d->program_resources.eventStackMap().fd(), stack_space_key,
      event_entry_type_ptr);

  auto null_event_stack_ptr =
      llvm::Constant::getNullValue(event_stack_ptr->getType());

  auto check_event_stack_ptr_condition =
      builder.CreateICmpEQ(null_event_stack_ptr, event_stack_ptr);

  auto invalid_event_stack_ptr_bb = llvm::BasicBlock::Create(
      context, "invalid_event_stack_ptr", enter_event_function);

  auto generate_event_header_bb = llvm::BasicBlock::Create(
      context, "generate_event_header", enter_event_function);

  builder.CreateCondBr(check_event_stack_ptr_condition,
                       invalid_event_stack_ptr_bb, generate_event_header_bb);

  builder.SetInsertPoint(invalid_event_stack_ptr_bb);
  builder.CreateRet(builder.getInt64(0));

  // Populate the event entry key
  builder.SetInsertPoint(generate_event_header_bb);
  builder.CreateStore(current_pid_tgid, event_entry_key);

  //
  // Generate the event header
  //

  auto event_header = builder.CreateGEP(
      event_stack_ptr, {builder.getInt32(0), builder.getInt32(0)});

  std::uint32_t field_index{0U};

  // Event entry size
  auto event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  auto event_entry_size = static_cast<std::uint32_t>(
      d->program_resources.eventStackMap().valueSize());

  builder.CreateStore(builder.getInt32(event_entry_size), event_header_field);

  ++field_index;

  // Event identifier
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  auto event_identifier = d->enter_event->eventIdentifier();
  builder.CreateStore(builder.getInt32(event_identifier), event_header_field);

  ++field_index;

  // Timestamp
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  auto event_header_field_value = bpf_prog_writer.bpf_ktime_get_ns();

  builder.CreateStore(event_header_field_value, event_header_field);

  ++field_index;

  // pid + tgid
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  builder.CreateStore(current_pid_tgid, event_header_field);

  ++field_index;

  // uid + gid
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  event_header_field_value = bpf_prog_writer.bpf_get_current_uid_gid();

  builder.CreateStore(event_header_field_value, event_header_field);

  ++field_index;

  // exit code
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  builder.CreateStore(builder.getInt64(0), event_header_field);

  ++field_index;

  // probe error flag
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  builder.CreateStore(builder.getInt64(0), event_header_field);

  //
  // Capture all arguments, without dereferencing pointers
  //

  auto generate_event_entry_bb = llvm::BasicBlock::Create(
      context, "generate_event_entry", enter_event_function);

  builder.CreateBr(generate_event_entry_bb);
  builder.SetInsertPoint(generate_event_entry_bb);

  auto event_data = builder.CreateGEP(
      event_stack_ptr, {builder.getInt32(0), builder.getInt32(1)});

  auto function_argument = enter_event_function->arg_begin();
  auto enter_event_struct = d->enter_event->structure();

  for (std::uint32_t source_index = 5U;
       source_index < enter_event_struct.size(); ++source_index) {

    const auto &enter_struct_field = enter_event_struct.at(source_index);

    auto param_bb = llvm::BasicBlock::Create(
        context, "capture_" + enter_struct_field.name, enter_event_function);

    builder.CreateBr(param_bb);
    builder.SetInsertPoint(param_bb);

    auto source_ptr =
        builder.CreateGEP(function_argument, {builder.getInt32(0),
                                              builder.getInt32(source_index)});

    auto value = builder.CreateLoad(source_ptr);

    auto destination_index = source_index - 5U;

    auto destination_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(destination_index)});

    builder.CreateStore(value, destination_ptr);
  }

  //
  // Store the event data we collected for later
  //

  bpf_prog_writer.bpf_map_update_elem(d->program_resources.eventMap().fd(),
                                      event_stack_ptr, event_entry_key,
                                      BPF_ANY);

  builder.CreateRet(builder.getInt64(0));

  //
  // Make sure the module is valid
  //

  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  if (llvm::verifyModule(module, &error_stream) != 0) {
    std::string error_message = "Module verification failed";
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    return StringError::create(error_message);
  }

  return {};
}

SuccessOrStringError
SyscallTracepoint::initializeExitFunction(BPFProgramWriter &bpf_prog_writer) {
  auto &builder = bpf_prog_writer.builder();
  auto &context = bpf_prog_writer.context();

  // Create the function
  auto event_function_exp = bpf_prog_writer.getExitFunction();

  if (!event_function_exp.succeeded()) {
    return event_function_exp.error();
  }

  auto exit_event_function = event_function_exp.takeValue();

  // Generate the entry basic block
  auto entry_bb =
      llvm::BasicBlock::Create(context, "entry", exit_event_function);

  builder.SetInsertPoint(entry_bb);

  // Allocate all buffers in advance
  auto event_entry_key = builder.CreateAlloca(builder.getInt64Ty());

  auto buffer_storage_entry_key = builder.CreateAlloca(builder.getInt32Ty());
  bpf_prog_writer.setValue("buffer_storage_entry_key",
                           buffer_storage_entry_key);

  // Get the event entry
  auto current_pid_tgid = bpf_prog_writer.bpf_get_current_pid_tgid();

  builder.CreateStore(current_pid_tgid, event_entry_key);

  auto event_entry_type_exp = bpf_prog_writer.getEventEntryType();
  if (!event_entry_type_exp.succeeded()) {
    return event_entry_type_exp.error();
  }

  auto event_entry_type = event_entry_type_exp.takeValue();
  auto event_entry_type_ptr = event_entry_type->getPointerTo();

  auto event_map_fd = d->program_resources.eventMap().fd();

  auto event_entry = bpf_prog_writer.bpf_map_lookup_elem(
      event_map_fd, event_entry_key, event_entry_type_ptr);

  bpf_prog_writer.setValue("event_entry", event_entry);

  auto null_event_entry_ptr =
      llvm::Constant::getNullValue(event_entry->getType());

  auto check_event_entry_ptr_condition =
      builder.CreateICmpEQ(null_event_entry_ptr, event_entry);

  auto invalid_event_entry_bb = llvm::BasicBlock::Create(
      context, "invalid_event_entry", exit_event_function);

  auto acquire_buffer_storage_index_bb = llvm::BasicBlock::Create(
      context, "acquire_buffer_storage_index", exit_event_function);

  builder.CreateCondBr(check_event_entry_ptr_condition, invalid_event_entry_bb,
                       acquire_buffer_storage_index_bb);

  builder.SetInsertPoint(invalid_event_entry_bb);
  builder.CreateRet(builder.getInt64(0));

  // Acquire the buffer storage index
  builder.SetInsertPoint(acquire_buffer_storage_index_bb);
  builder.CreateStore(builder.getInt32(0), buffer_storage_entry_key);

  auto &buffer_storage_impl = static_cast<BufferStorage &>(d->buffer_storage);

  auto buffer_storage_index = bpf_prog_writer.bpf_map_lookup_elem(
      buffer_storage_impl.indexMap(), buffer_storage_entry_key,
      llvm::Type::getInt32PtrTy(context));

  bpf_prog_writer.setValue("buffer_storage_index", buffer_storage_index);

  auto null_buffer_storage_index =
      llvm::Constant::getNullValue(buffer_storage_index->getType());

  auto check_buffer_storage_index_condition =
      builder.CreateICmpEQ(buffer_storage_index, null_buffer_storage_index);

  auto invalid_buffer_storage_index_bb = llvm::BasicBlock::Create(
      context, "invalid_buffer_storage_index", exit_event_function);

  auto acquire_buffer_stack_bb = llvm::BasicBlock::Create(
      context, "acquire_buffer_stack", exit_event_function);

  builder.CreateCondBr(check_buffer_storage_index_condition,
                       invalid_buffer_storage_index_bb,
                       acquire_buffer_stack_bb);

  builder.SetInsertPoint(invalid_buffer_storage_index_bb);
  builder.CreateRet(builder.getInt64(0));

  // Acquire the buffer stack
  builder.SetInsertPoint(acquire_buffer_stack_bb);

  auto buffer_stack_map_fd = d->program_resources.bufferStackMap().fd();

  auto buffer_storage_stack = bpf_prog_writer.bpf_map_lookup_elem(
      buffer_stack_map_fd, buffer_storage_entry_key, builder.getInt8PtrTy());

  bpf_prog_writer.setValue("buffer_storage_stack", buffer_storage_stack);

  auto null_buffer_stack =
      llvm::Constant::getNullValue(buffer_storage_stack->getType());

  auto check_buffer_stack_condition =
      builder.CreateICmpEQ(buffer_storage_stack, null_buffer_stack);

  auto invalid_buffer_stack_bb = llvm::BasicBlock::Create(
      context, "invalid_buffer_stack", exit_event_function);

  auto update_exit_code_bb = llvm::BasicBlock::Create(
      context, "update_exit_code", exit_event_function);

  builder.CreateCondBr(check_buffer_stack_condition, invalid_buffer_stack_bb,
                       update_exit_code_bb);

  builder.SetInsertPoint(invalid_buffer_stack_bb);
  builder.CreateRet(builder.getInt64(0));

  // Fill in the the exit code of the function
  builder.SetInsertPoint(update_exit_code_bb);

  auto exit_event_struct = d->exit_event->structure();

  // clang-format off
  auto exit_code_it = std::find_if(
    exit_event_struct.begin(),
    exit_event_struct.end(),

    [](const auto &structure_field) -> bool {
      return structure_field.name == "ret";
    }
  );
  // clang-format on

  if (exit_code_it == exit_event_struct.end()) {
    return StringError::create("Failed to locate the syscall exit code");
  }

  auto exit_code_index =
      static_cast<std::uint32_t>(exit_code_it - exit_event_struct.begin());

  auto exit_code_struct_index = builder.getInt32(exit_code_index);

  auto exit_code =
      builder.CreateGEP(exit_event_function->arg_begin(),
                        {builder.getInt32(0), exit_code_struct_index});

  auto exit_code_value = builder.CreateLoad(exit_code);

  auto event_header = builder.CreateGEP(
      event_entry, {builder.getInt32(0), builder.getInt32(0)});

  auto header_exit_code = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(5)});

  builder.CreateStore(exit_code_value, header_exit_code);

  // Create a new block for the serializer
  auto serializer_entry_bb = llvm::BasicBlock::Create(
      context, "serializer_entry", exit_event_function);

  builder.CreateBr(serializer_entry_bb);
  builder.SetInsertPoint(serializer_entry_bb);

  return {};
}

SuccessOrStringError
SyscallTracepoint::finalizeExitFunction(BPFProgramWriter &bpf_prog_writer) {
  // Make sure the event entry is defined; it's what we have to write
  auto value_exp = bpf_prog_writer.value("event_entry");
  if (!value_exp.succeeded()) {
    return StringError::create("The event_entry value is not set");
  }

  auto event_entry = value_exp.takeValue();

  auto event_entry_size = static_cast<std::uint32_t>(
      d->program_resources.eventStackMap().valueSize());

  // Get the exit function
  auto &builder = bpf_prog_writer.builder();
  auto &context = bpf_prog_writer.context();

  auto exit_function_exp = bpf_prog_writer.getExitFunction();

  if (!exit_function_exp.succeeded()) {
    return exit_function_exp.error();
  }

  auto exit_function = exit_function_exp.takeValue();

  // Create a new basic block
  auto finalize_bb =
      llvm::BasicBlock::Create(context, "finalize", exit_function);

  builder.CreateBr(finalize_bb);
  builder.SetInsertPoint(finalize_bb);

  // Send the event entry through perf_event
  auto perf_event_array_fd = d->perf_event_array.fd();

  auto success_exp = bpf_prog_writer.bpf_perf_event_output(
      perf_event_array_fd, static_cast<std::uint32_t>(-1LL), event_entry,
      event_entry_size);

  // Terminate the function
  builder.CreateRet(builder.getInt64(0));

  // Make sure the module is still valid
  auto &module = bpf_prog_writer.module();

  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  if (llvm::verifyModule(module, &error_stream) != 0) {
    std::string error_message = "Module verification failed";
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    return StringError::create(error_message);
  }

  return {};
}

StringErrorOr<std::vector<std::string>>
SyscallTracepoint::getTracepointEnableSwitchList() {

  std::vector<std::string> tracepoint_switch_list;

  auto switch_path_exp =
      d->enter_event->path(ebpf::TracepointEvent::PathType::EnableSwitch);

  if (!switch_path_exp.succeeded()) {
    return switch_path_exp.error();
  }

  tracepoint_switch_list.push_back(switch_path_exp.takeValue());

  switch_path_exp =
      d->exit_event->path(ebpf::TracepointEvent::PathType::EnableSwitch);

  if (!switch_path_exp.succeeded()) {
    return switch_path_exp.error();
  }

  tracepoint_switch_list.push_back(switch_path_exp.takeValue());

  return tracepoint_switch_list;
}

SuccessOrStringError SyscallTracepoint::enableTracepoints() {
  auto tracepoint_switch_list_exp = getTracepointEnableSwitchList();

  if (!tracepoint_switch_list_exp.succeeded()) {
    return tracepoint_switch_list_exp.error();
  }

  auto tracepoint_switch_list = tracepoint_switch_list_exp.takeValue();

  for (const auto &tracepoint_switch : tracepoint_switch_list) {
    auto switch_file = std::fstream(tracepoint_switch, std::ios::out);
    switch_file << "1";

    if (!switch_file) {
      return StringError::create("Failed to write to the switch file");
    }
  }

  return {};
}

SuccessOrStringError SyscallTracepoint::disableTracepoints() {
  auto tracepoint_switch_list_exp = getTracepointEnableSwitchList();

  if (!tracepoint_switch_list_exp.succeeded()) {
    return tracepoint_switch_list_exp.error();
  }

  auto tracepoint_switch_list = tracepoint_switch_list_exp.takeValue();

  for (const auto &tracepoint_switch : tracepoint_switch_list) {
    auto switch_file = std::fstream(tracepoint_switch, std::ios::out);
    switch_file << "0";

    if (!switch_file) {
      return StringError::create("Failed to write to the switch file");
    }
  }

  return {};
}

StringErrorOr<ISyscallTracepoint::Ref> ISyscallTracepoint::create(
    const std::string &syscall_name, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size) {

  try {
    return Ref(new SyscallTracepoint(syscall_name, buffer_storage,
                                     perf_event_array, event_map_size));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
