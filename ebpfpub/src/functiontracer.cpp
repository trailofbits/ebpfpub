/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "functiontracer.h"
#include "abi.h"
#include "syscallserializerfactory.h"

#include <atomic>

#include <llvm/IR/Verifier.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/iperfevent.h>
#include <tob/ebpf/llvm_utils.h>
#include <tob/ebpf/tracepointdescriptor.h>

namespace tob::ebpfpub {
namespace {
using EventMap = ebpf::BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;
using StackMap = ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

const std::string kLLVMModuleName{"FunctionTracer"};

const std::string kSyscallsEventCategory{"syscalls"};
const std::string kEnterEventNamePrefix{"sys_enter_"};
const std::string kExitEventNamePrefix{"sys_exit_"};

void initializeSerializerFactoryHelper() {
  static const auto serializers_initialized_exp = initializeSerializerFactory();

  if (serializers_initialized_exp.failed()) {
    throw serializers_initialized_exp.error();
  }
}

std::uint32_t generateKprobeIdentifier() {
  static std::atomic_uint32_t identifier_generator{0U};
  return ++identifier_generator;
}
} // namespace

struct FunctionTracer::PrivateData final {
  PrivateData(IBufferStorage &buffer_storage_,
              ebpf::PerfEventArray &perf_event_array_)
      : buffer_storage(buffer_storage_), perf_event_array(perf_event_array_) {}

  EventData event_data;
  IFunctionSerializer::Ref serializer;

  std::size_t event_map_size;
  IBufferStorage &buffer_storage;
  ebpf::PerfEventArray &perf_event_array;

  llvm::LLVMContext llvm_context;
  std::unique_ptr<llvm::Module> llvm_module;

  BPFProgramWriter::ProgramResources program_resources;

  utils::UniqueFd enter_program;
  utils::UniqueFd exit_program;
};

FunctionTracer::~FunctionTracer() {}

const std::string &FunctionTracer::name() const { return d->event_data.name; }

std::uint32_t FunctionTracer::eventIdentifier() const {
  return d->event_data.enter_event->identifier();
}

StringErrorOr<IFunctionSerializer::EventList>
FunctionTracer::parseEvents(IBufferReader &buffer_reader) const {
  IFunctionSerializer::EventList event_list;

  auto &buffer_storage_impl = static_cast<BufferStorage &>(d->buffer_storage);

  for (;;) {
    if (buffer_reader.availableBytes() < 8U) {
      return StringError::create("Not enough bytes to read the event");
    }

    auto entry_size = buffer_reader.peekU32(0U);
    auto event_identifier = buffer_reader.peekU32(4U);
    if (event_identifier != d->event_data.enter_event->identifier()) {
      break;
    }

    entry_size -= 8U;

    if (entry_size > buffer_reader.availableBytes()) {
      return StringError::create("Not enough bytes to read the event");
    }

    buffer_reader.skipBytes(8U);

    IFunctionSerializer::Event event = {};
    event.name = d->event_data.name;

    event.header.timestamp = buffer_reader.u64();
    event.header.parent_process_id = 0U;
    event.header.thread_id = static_cast<pid_t>(buffer_reader.u32());
    event.header.process_id = static_cast<pid_t>(buffer_reader.u32());
    event.header.user_id = buffer_reader.u32();
    event.header.group_id = buffer_reader.u32();
    event.header.exit_code = buffer_reader.u64();
    event.header.probe_error = (buffer_reader.u64() != 0U);

    auto success_exp =
        d->serializer->parseEvents(event, buffer_reader, buffer_storage_impl);

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

FunctionTracer::FunctionTracer(EventData event_data,
                               IFunctionSerializer::Ref serializer,
                               std::size_t event_map_size,
                               IBufferStorage &buffer_storage,
                               ebpf::PerfEventArray &perf_event_array)
    : d(new PrivateData(buffer_storage, perf_event_array)) {

  d->event_data = std::move(event_data);
  d->serializer = std::move(serializer);

  // Initialize the LLVM module
  d->llvm_module = ebpf::createLLVMModule(d->llvm_context, kLLVMModuleName);
  if (!d->llvm_module) {
    throw StringError::create("Failed to generate the LLVM BPF module");
  }

  // Create the BPF writer helper
  auto &buffer_storage_impl = static_cast<BufferStorage &>(d->buffer_storage);

  auto bpf_program_writer_exp = BPFProgramWriter::create(
      *d->llvm_module.get(), buffer_storage_impl, d->event_data.enter_structure,
      d->event_data.exit_structure, d->event_data.program_type);

  if (!bpf_program_writer_exp.succeeded()) {
    throw bpf_program_writer_exp.error();
  }

  auto bpf_program_writer_ref = bpf_program_writer_exp.takeValue();

  auto &bpf_program_writer_impl =
      *static_cast<BPFProgramWriter *>(bpf_program_writer_ref.get());

  // Initialize the types and the internal maps
  auto program_resources_exp =
      bpf_program_writer_impl.initializeProgram(event_map_size);

  if (!program_resources_exp.succeeded()) {
    throw program_resources_exp.error();
  }

  d->program_resources = program_resources_exp.takeValue();

  // Generate the common enter function
  auto success_exp = generateEnterFunction(bpf_program_writer_impl);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  bpf_program_writer_impl.clearSavedValues();

  // Initialize the exit function
  success_exp = initializeExitFunction(bpf_program_writer_impl);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Use the serializer we have been given to complete the exit function
  success_exp = d->serializer->generate(d->event_data.enter_structure,
                                        bpf_program_writer_impl);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Finalize the exit function
  success_exp = finalizeExitFunction(bpf_program_writer_impl);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Compile the module; we'll obtain one program for the enter event, and
  // another one for the exit event
  auto &module = *d->llvm_module.get();

  auto program_map_exp = ebpf::compileModule(module);
  if (!program_map_exp.succeeded()) {
    throw program_map_exp.error();
  }

  auto program_map = program_map_exp.takeValue();

  auto enter_program_it = program_map.find("on_syscall_enter_section");
  if (enter_program_it == program_map.end()) {
    throw StringError::create("Failed to compile the enter program");
  }

  auto &enter_program = enter_program_it->second;

  auto exit_program_it = program_map.find("on_syscall_exit_section");
  if (exit_program_it == program_map.end()) {
    throw StringError::create("Failed to compile the exit program");
  }

  auto &exit_program = exit_program_it->second;

  // Load the enter program
  auto program_exp =
      ebpf::loadProgram(enter_program, *d->event_data.enter_event.get());

  if (!program_exp.succeeded()) {
    auto load_error = "The 'enter' program could not be loaded: " +
                      program_exp.error().message();

    throw StringError::create(load_error);
  }

  d->enter_program = program_exp.takeValue();

  // Load the exit program
  program_exp =
      ebpf::loadProgram(exit_program, *d->event_data.exit_event.get());

  if (!program_exp.succeeded()) {
    auto load_error = "The 'exit' program could not be loaded: " +
                      program_exp.error().message();

    throw StringError::create(load_error);
  }

  d->exit_program = program_exp.takeValue();
}

SuccessOrStringError
FunctionTracer::generateEnterFunction(BPFProgramWriter &bpf_prog_writer) {
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
  auto &bpf_syscall_interface = bpf_prog_writer.bpfSyscallInterface();
  auto current_pid_tgid = bpf_syscall_interface.getCurrentPidTgid();

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

  auto event_stack_ptr = bpf_syscall_interface.mapLookupElem(
      d->program_resources.event_stack_map->fd(), stack_space_key,
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
      d->program_resources.event_stack_map->valueSize());

  builder.CreateStore(builder.getInt32(event_entry_size), event_header_field);

  ++field_index;

  // Event identifier
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  auto event_identifier =
      builder.getInt32(d->event_data.enter_event->identifier());

  builder.CreateStore(event_identifier, event_header_field);

  ++field_index;

  // Timestamp
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(field_index)});

  auto event_header_field_value = bpf_syscall_interface.ktimeGetNs();

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

  event_header_field_value = bpf_syscall_interface.getCurrentUidGid();

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

  // Tracepoints always start with a header made of 5 fields, while Kprobes
  // use the pt_regs structure
  std::uint32_t base_struct_index{0U};
  if (d->event_data.program_type == BPFProgramWriter::ProgramType::Tracepoint) {
    base_struct_index = 5U;
  }

  for (std::uint32_t source_index = base_struct_index;
       source_index < d->event_data.enter_structure.size(); ++source_index) {

    const auto &enter_struct_field =
        d->event_data.enter_structure.at(source_index);

    auto param_bb = llvm::BasicBlock::Create(
        context, "capture_" + enter_struct_field.name, enter_event_function);

    builder.CreateBr(param_bb);
    builder.SetInsertPoint(param_bb);

    auto destination_index = source_index - base_struct_index;
    auto destination_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(destination_index)});

    llvm::Value *source_ptr = nullptr;
    if (d->event_data.program_type ==
        BPFProgramWriter::ProgramType::Tracepoint) {
      auto function_argument = enter_event_function->arg_begin();

      source_ptr = builder.CreateGEP(
          function_argument,
          {builder.getInt32(0), builder.getInt32(source_index)});

    } else {
      auto pt_regs_ptr = enter_event_function->arg_begin();

      if (d->event_data.program_type == BPFProgramWriter::ProgramType::Kprobe) {
        // TODO: overwrite pt_regs_ptr with the user pt_regs
      }

      auto source_ptr_exp = getRegisterForParameterIndex(
          builder, pt_regs_ptr, source_index, destination_ptr->getType());

      if (!source_ptr_exp.succeeded()) {
        return source_ptr_exp.error();
      }

      source_ptr = source_ptr_exp.takeValue();
    }

    auto value = builder.CreateLoad(source_ptr);
    builder.CreateStore(value, destination_ptr);
  }

  //
  // Store the event data we collected for later
  //

  bpf_syscall_interface.mapUpdateElem(d->program_resources.event_map->fd(),
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
FunctionTracer::initializeExitFunction(BPFProgramWriter &bpf_prog_writer) {
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
  auto &bpf_syscall_interface = bpf_prog_writer.bpfSyscallInterface();

  auto current_pid_tgid = bpf_syscall_interface.getCurrentPidTgid();
  builder.CreateStore(current_pid_tgid, event_entry_key);

  auto event_entry_type_exp = bpf_prog_writer.getEventEntryType();
  if (!event_entry_type_exp.succeeded()) {
    return event_entry_type_exp.error();
  }

  auto event_entry_type = event_entry_type_exp.takeValue();
  auto event_entry_type_ptr = event_entry_type->getPointerTo();
  auto event_map_fd = d->program_resources.event_map->fd();

  auto event_entry = bpf_syscall_interface.mapLookupElem(
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

  auto buffer_storage_index = bpf_syscall_interface.mapLookupElem(
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

  auto buffer_stack_map_fd = d->program_resources.buffer_stack_map->fd();

  auto buffer_storage_stack = bpf_syscall_interface.mapLookupElem(
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

  llvm::Value *exit_code_value{nullptr};

  if (d->event_data.program_type == BPFProgramWriter::ProgramType::Tracepoint) {
    // clang-format off
    auto exit_code_it = std::find_if(
      d->event_data.exit_structure.begin(),
      d->event_data.exit_structure.end(),

      [](const auto &structure_field) -> bool {
        return structure_field.name == "ret";
      }
    );
    // clang-format on

    if (exit_code_it == d->event_data.exit_structure.end()) {
      return StringError::create(
          "Failed to locate the tracepoint syscall exit code");
    }

    auto exit_code_index = static_cast<std::uint32_t>(
        exit_code_it - d->event_data.exit_structure.begin());

    auto exit_code_struct_index = builder.getInt32(exit_code_index);

    auto exit_code =
        builder.CreateGEP(exit_event_function->arg_begin(),
                          {builder.getInt32(0), exit_code_struct_index});

    exit_code_value = builder.CreateLoad(exit_code);

  } else {
    auto exit_code_exp = getPtRegsParameterFromName(
        builder, exit_event_function->arg_begin(), "rax");

    if (!exit_code_exp.succeeded()) {
      return StringError::create("Failed to locate the syscall exit code");
    }

    auto exit_code = exit_code_exp.takeValue();
    exit_code_value = builder.CreateLoad(exit_code);
  }

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
FunctionTracer::finalizeExitFunction(BPFProgramWriter &bpf_prog_writer) {
  // Make sure the event entry is defined; it's what we have to write
  auto value_exp = bpf_prog_writer.value("event_entry");
  if (!value_exp.succeeded()) {
    return StringError::create("The event_entry value is not set");
  }

  auto event_entry = value_exp.takeValue();

  auto event_entry_size = static_cast<std::uint32_t>(
      d->program_resources.event_stack_map->valueSize());

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
  auto bpf_context = exit_function->arg_begin();
  auto &bpf_syscall_interface = bpf_prog_writer.bpfSyscallInterface();

  bpf_syscall_interface.perfEventOutput(bpf_context, perf_event_array_fd,
                                        static_cast<std::uint32_t>(-1LL),
                                        event_entry, event_entry_size);

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

StringErrorOr<IFunctionTracer::Ref>
IFunctionTracer::createFromSyscallTracepoint(
    const std::string &name, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size) {

  initializeSerializerFactoryHelper();

  FunctionTracer::EventData event_data;
  event_data.program_type = BPFProgramWriter::ProgramType::Tracepoint;
  event_data.name = name;

  // Create the enter tracepoint event
  auto event_name = kEnterEventNamePrefix + name;

  auto tracepoint_desc_exp =
      ebpf::TracepointDescriptor::create(kSyscallsEventCategory, event_name);

  if (!tracepoint_desc_exp.succeeded()) {
    throw tracepoint_desc_exp.error();
  }

  auto enter_tracepoint_desc = tracepoint_desc_exp.takeValue();
  event_data.enter_structure = enter_tracepoint_desc->structure();

  event_name = kSyscallsEventCategory + "/" + event_name;
  auto perf_event_exp = ebpf::IPerfEvent::createTracepoint(
      event_name, enter_tracepoint_desc->eventIdentifier());

  if (!perf_event_exp.succeeded()) {
    throw perf_event_exp.error();
  }

  event_data.enter_event = perf_event_exp.takeValue();

  // Create the exit tracepoint event
  event_name = kExitEventNamePrefix + name;

  tracepoint_desc_exp =
      ebpf::TracepointDescriptor::create(kSyscallsEventCategory, event_name);

  if (!tracepoint_desc_exp.succeeded()) {
    throw tracepoint_desc_exp.error();
  }

  auto exit_tracepoint_desc = tracepoint_desc_exp.takeValue();
  event_data.exit_structure = exit_tracepoint_desc->structure();

  event_name = kSyscallsEventCategory + "/" + event_name;
  perf_event_exp = ebpf::IPerfEvent::createTracepoint(
      event_name, exit_tracepoint_desc->eventIdentifier());

  if (!perf_event_exp.succeeded()) {
    throw perf_event_exp.error();
  }

  event_data.exit_event = perf_event_exp.takeValue();

  // Obtain a syscall serializer
  auto serializer_ref_exp = createSerializer(name);
  if (!serializer_ref_exp.succeeded()) {
    throw serializer_ref_exp.error();
  }

  auto serializer_ref = serializer_ref_exp.takeValue();

  try {
    return Ref(new FunctionTracer(std::move(event_data),
                                  std::move(serializer_ref), event_map_size,
                                  buffer_storage, perf_event_array));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IFunctionTracer::Ref> IFunctionTracer::createFromKprobe(
    const std::string &name, const ebpf::Structure &args,
    IBufferStorage &buffer_storage, ebpf::PerfEventArray &perf_event_array,
    std::size_t event_map_size, IFunctionSerializer::Ref serializer) {

  FunctionTracer::EventData event_data;
  event_data.program_type = BPFProgramWriter::ProgramType::Kprobe;
  event_data.name = name;
  event_data.enter_structure = args;

  auto identifier = generateKprobeIdentifier();

  auto event_exp = ebpf::IPerfEvent::createKprobe(name, false, identifier);
  if (!event_exp.succeeded()) {
    return event_exp.error();
  }

  event_data.enter_event = event_exp.takeValue();

  event_exp = ebpf::IPerfEvent::createKprobe(name, true, identifier);
  if (!event_exp.succeeded()) {
    return event_exp.error();
  }

  event_data.exit_event = event_exp.takeValue();

  try {
    return Ref(new FunctionTracer(std::move(event_data), std::move(serializer),
                                  event_map_size, buffer_storage,
                                  perf_event_array));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IFunctionTracer::Ref> IFunctionTracer::createFromUprobe(
    const std::string &name, const std::string &path,
    const ebpf::Structure &args, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size,
    IFunctionSerializer::Ref serializer) {

  initializeSerializerFactoryHelper();

  FunctionTracer::EventData event_data;
  event_data.program_type = BPFProgramWriter::ProgramType::Uprobe;
  event_data.name = name;
  event_data.enter_structure = args;

  auto identifier = generateKprobeIdentifier();

  auto event_exp =
      ebpf::IPerfEvent::createUprobe(name, path, false, identifier);

  if (!event_exp.succeeded()) {
    return event_exp.error();
  }

  event_data.enter_event = event_exp.takeValue();

  event_exp = ebpf::IPerfEvent::createUprobe(name, path, true, identifier);
  if (!event_exp.succeeded()) {
    return event_exp.error();
  }

  event_data.exit_event = event_exp.takeValue();

  try {
    return Ref(new FunctionTracer(std::move(event_data), std::move(serializer),
                                  event_map_size, buffer_storage,
                                  perf_event_array));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
