/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "bpfprogramwriter.h"

#include <linux/bpf.h>

#include <tob/ebpf/llvm_utils.h>

namespace tob::ebpfpub {
namespace {
const std::string kEnterEventDataTypeName{"EnterEventData"};
const std::string kExitEventDataTypeName{"ExitEventData"};
const std::string kEventHeaderTypeName{"EventHeader"};
const std::string kEventDataTypeName{"EventData"};
const std::string kEventEntryTypeName{"EventEntry"};

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
} // namespace

struct BPFProgramWriter::PrivateData final {
  PrivateData(llvm::Module &module_, IBufferStorage &buffer_storage_)
      : module(module_), context(module_.getContext()), builder(context),
        buffer_storage(buffer_storage_) {}

  llvm::Module &module;
  llvm::LLVMContext &context;

  llvm::IRBuilder<> builder;
  ebpf::BPFSyscallInterface::Ref bpf_syscall_interface;

  IBufferStorage &buffer_storage;

  ebpf::Structure enter_structure;
  ebpf::Structure exit_structure;
  ProgramType program_type{ProgramType::Tracepoint};

  std::unordered_map<std::string, llvm::Value *> saved_value_map;
};

StringErrorOr<BPFProgramWriter::Ref>
BPFProgramWriter::create(llvm::Module &module, IBufferStorage &buffer_storage,
                         const ebpf::Structure &enter_structure,
                         const ebpf::Structure &exit_structure,
                         ProgramType program_type) {

  try {
    return Ref(new BPFProgramWriter(module, buffer_storage, enter_structure,
                                    exit_structure, program_type));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

BPFProgramWriter::~BPFProgramWriter() {}

llvm::IRBuilder<> &BPFProgramWriter::builder() { return d->builder; }

ebpf::BPFSyscallInterface &BPFProgramWriter::bpfSyscallInterface() {
  return *d->bpf_syscall_interface.get();
}

llvm::Module &BPFProgramWriter::module() { return d->module; }

llvm::LLVMContext &BPFProgramWriter::context() { return d->context; }

BPFProgramWriter::ProgramType BPFProgramWriter::programType() const {
  return d->program_type;
}

StringErrorOr<llvm::Function *> BPFProgramWriter::getExitFunction() {
  auto function = module().getFunction("on_syscall_exit");
  if (function == nullptr) {
    return StringError::create("The program has not been initialized");
  }

  return function;
}

StringErrorOr<llvm::Function *> BPFProgramWriter::getEnterFunction() {
  auto function = module().getFunction("on_syscall_enter");
  if (function == nullptr) {
    return StringError::create("The program has not been initialized");
  }

  return function;
}

StringErrorOr<llvm::Type *> BPFProgramWriter::getEventEntryType() {
  auto type = module().getTypeByName(kEventEntryTypeName);
  if (type == nullptr) {
    return StringError::create("The program has not been initialized");
  }

  return type;
}

StringErrorOr<llvm::Value *> BPFProgramWriter::value(const std::string &name) {
  auto saved_value_it = d->saved_value_map.find(name);
  if (saved_value_it == d->saved_value_map.end()) {
    return StringError::create("The specified value was not found");
  }

  return saved_value_it->second;
}

StringErrorOr<llvm::Value *> BPFProgramWriter::generateBufferStorageIndex() {
  // Get the buffer storage index
  auto value_exp = value("buffer_storage_index");
  if (!value_exp.succeeded()) {
    return StringError::create("The buffer_storage_index value is not set");
  }

  auto buffer_storage_index = value_exp.takeValue();

  // When generating a new index; we make sure we stay within the
  // size of the buffer storage
  auto buffer_index_value = builder().CreateLoad(buffer_storage_index);

  auto next_buffer_index_value = builder().CreateBinOp(
      llvm::Instruction::Add, buffer_index_value, builder().getInt32(1));

  auto buffer_storage_entry_count =
      static_cast<std::uint32_t>(d->buffer_storage.bufferCount());

  next_buffer_index_value =
      builder().CreateBinOp(llvm::Instruction::URem, next_buffer_index_value,
                            builder().getInt32(buffer_storage_entry_count));

  builder().CreateStore(next_buffer_index_value, buffer_storage_index);

  return next_buffer_index_value;
}

StringErrorOr<llvm::Value *>
BPFProgramWriter::markBufferStorageIndex(llvm::Value *buffer_storage_index) {
  // Get or retrieve the current the processor id
  auto value_exp = value("current_processor_id");
  if (!value_exp.succeeded()) {
    auto current_processor_id = d->bpf_syscall_interface->getSmpProcessorId();

    current_processor_id =
        builder().CreateZExt(current_processor_id, builder().getInt64Ty());

    current_processor_id = builder().CreateBinOp(
        llvm::Instruction::Shl, current_processor_id, builder().getInt64(48U));

    current_processor_id =
        builder().CreateBinOp(llvm::Instruction::Or, current_processor_id,
                              builder().getInt64(0xFF00000000000000ULL));

    setValue("current_processor_id", current_processor_id);
    value_exp = current_processor_id;
  }

  if (!value_exp.succeeded()) {
    return value_exp.error();
  }

  auto current_processor_id = value_exp.takeValue();

  auto marked_buffer_index =
      builder().CreateZExt(buffer_storage_index, builder().getInt64Ty());

  marked_buffer_index = builder().CreateBinOp(
      llvm::Instruction::Or, marked_buffer_index, current_processor_id);

  return marked_buffer_index;
}

SuccessOrStringError
BPFProgramWriter::captureString(llvm::Value *string_pointer) {
  // Make sure we have all the required values
  auto value_exp = value("probe_error_flag");
  if (!value_exp.succeeded()) {
    // Get the event entry
    value_exp = value("event_entry");
    if (!value_exp.succeeded()) {
      return StringError::create("The event_entry value is not set");
    }

    auto event_entry = value_exp.takeValue();

    // Get the header
    auto event_header = builder().CreateGEP(
        event_entry, {builder().getInt32(0), builder().getInt32(0)});

    // Get the probe error flag
    auto probe_error_flag = builder().CreateGEP(
        event_header, {builder().getInt32(0), builder().getInt32(6U)});

    value_exp = probe_error_flag;
    setValue("probe_error_flag", probe_error_flag);
  }

  if (!value_exp.succeeded()) {
    return value_exp.error();
  }

  auto probe_error_flag = value_exp.takeValue();

  value_exp = value("buffer_storage_entry_key");
  if (!value_exp.succeeded()) {
    return StringError::create("The buffer_storage_entry_key value is not set");
  }

  auto buffer_storage_entry_key = value_exp.takeValue();

  value_exp = value("buffer_storage_stack");
  if (!value_exp.succeeded()) {
    return StringError::create("The buffer_storage_stack value is not set");
  }

  auto buffer_storage_stack = value_exp.takeValue();

  // Get the buffer storage fd and entry size
  auto buffer_storage_entry_size = d->buffer_storage.bufferSize();
  auto buffer_storage_fd = d->buffer_storage.bufferMap();

  // Read the user memory
  auto pointer_value = builder().CreateLoad(string_pointer);

  auto read_error = d->bpf_syscall_interface->probeReadStr(
      buffer_storage_stack, buffer_storage_entry_size, pointer_value);

  read_error = builder().CreateBinOp(llvm::Instruction::And, read_error,
                                     builder().getInt64(0x8000000000000000ULL));

  read_error =
      builder().CreateBinOp(llvm::Instruction::Or,
                            builder().CreateLoad(probe_error_flag), read_error);

  builder().CreateStore(read_error, probe_error_flag);

  auto buffer_storage_index_exp = generateBufferStorageIndex();
  if (!buffer_storage_index_exp.succeeded()) {
    return buffer_storage_index_exp.error();
  }

  auto buffer_storage_index = buffer_storage_index_exp.takeValue();

  // Save the string to the buffer storage
  builder().CreateStore(buffer_storage_index, buffer_storage_entry_key);

  d->bpf_syscall_interface->mapUpdateElem(buffer_storage_fd,
                                          buffer_storage_stack,
                                          buffer_storage_entry_key, BPF_ANY);

  // Update the string pointer
  auto marked_index_exp = markBufferStorageIndex(buffer_storage_index);

  if (!marked_index_exp.succeeded()) {
    return marked_index_exp.error();
  }

  auto marked_index = marked_index_exp.takeValue();

  marked_index = builder().CreateIntToPtr(
      marked_index, string_pointer->getType()->getPointerElementType());

  builder().CreateStore(marked_index, string_pointer);
  return {};
}

SuccessOrStringError
BPFProgramWriter::captureBuffer(llvm::Value *buffer_pointer,
                                llvm::Value *buffer_size) {

  // Make sure we have all the required values
  auto value_exp = value("probe_error_flag");
  if (!value_exp.succeeded()) {
    // Get the event entry
    value_exp = value("event_entry");
    if (!value_exp.succeeded()) {
      return StringError::create("The event_entry value is not set");
    }

    auto event_entry = value_exp.takeValue();

    // Get the header
    auto event_header = builder().CreateGEP(
        event_entry, {builder().getInt32(0), builder().getInt32(0)});

    // Get the probe error flag
    auto probe_error_flag = builder().CreateGEP(
        event_header, {builder().getInt32(0), builder().getInt32(6U)});

    value_exp = probe_error_flag;
    setValue("probe_error_flag", probe_error_flag);
  }

  if (!value_exp.succeeded()) {
    return value_exp.error();
  }

  auto probe_error_flag = value_exp.takeValue();

  value_exp = value("buffer_storage_entry_key");
  if (!value_exp.succeeded()) {
    return StringError::create("The buffer_storage_entry_key value is not set");
  }

  auto buffer_storage_entry_key = value_exp.takeValue();

  value_exp = value("buffer_storage_stack");
  if (!value_exp.succeeded()) {
    return StringError::create("The buffer_storage_stack value is not set");
  }

  auto buffer_storage_stack = value_exp.takeValue();

  // Read the user memory
  auto pointer_value = builder().CreateLoad(buffer_pointer);

  auto read_error = d->bpf_syscall_interface->probeRead(
      buffer_storage_stack, buffer_size, pointer_value);

  read_error = builder().CreateBinOp(llvm::Instruction::And, read_error,
                                     builder().getInt64(0x8000000000000000ULL));

  read_error =
      builder().CreateBinOp(llvm::Instruction::Or,
                            builder().CreateLoad(probe_error_flag), read_error);

  builder().CreateStore(read_error, probe_error_flag);

  auto buffer_storage_index_exp = generateBufferStorageIndex();
  if (!buffer_storage_index_exp.succeeded()) {
    return buffer_storage_index_exp.error();
  }

  auto buffer_storage_index = buffer_storage_index_exp.takeValue();

  // Save the string to the buffer storage
  builder().CreateStore(buffer_storage_index, buffer_storage_entry_key);

  auto buffer_storage_fd = d->buffer_storage.bufferMap();

  d->bpf_syscall_interface->mapUpdateElem(buffer_storage_fd,
                                          buffer_storage_stack,
                                          buffer_storage_entry_key, BPF_ANY);

  // Update the string pointer
  auto marked_index_exp = markBufferStorageIndex(buffer_storage_index);

  if (!marked_index_exp.succeeded()) {
    return marked_index_exp.error();
  }

  auto marked_index = marked_index_exp.takeValue();

  marked_index =
      builder().CreateIntToPtr(marked_index, builder().getInt8PtrTy());

  builder().CreateStore(marked_index, buffer_pointer);

  return {};
}

StringErrorOr<BPFProgramWriter::ProgramResources>
BPFProgramWriter::initializeProgram(std::size_t event_map_size) {
  // Define the event header type

  // clang-format off
  std::vector<llvm::Type *> type_list = {
    // Event entry size
    llvm::Type::getInt32Ty(context()),

    // Event identifier
    llvm::Type::getInt32Ty(context()),

    // Timestamp
    llvm::Type::getInt64Ty(context()),

    // PID, TGID
    llvm::Type::getInt64Ty(context()),

    // UID, GID
    llvm::Type::getInt64Ty(context()),

    // Exit code
    llvm::Type::getInt64Ty(context()),

    // Probe error flag
    llvm::Type::getInt64Ty(context())
  };
  // clang-format on

  auto existing_type_ptr = module().getTypeByName(kEventHeaderTypeName);
  if (existing_type_ptr != nullptr) {
    return StringError::create("A type named " + kEventHeaderTypeName +
                               " is already defined");
  }

  auto event_header =
      llvm::StructType::create(type_list, kEventHeaderTypeName, true);

  if (event_header == nullptr) {
    return StringError::create("Failed to create the event header type");
  }

  // Define the function types; use the format file for tracepoints and the
  // pt_regs structure for everything else
  if (d->program_type == ProgramType::Tracepoint) {
    auto type_exp = importTracepointDescriptorStructure(
        d->enter_structure, kEnterEventDataTypeName);

    if (!type_exp.succeeded()) {
      return type_exp.error();
    }

    type_exp = importTracepointDescriptorStructure(d->exit_structure,
                                                   kExitEventDataTypeName);

    if (!type_exp.succeeded()) {
      return type_exp.error();
    }

  } else {
    type_list =
        std::vector<llvm::Type *>(21U, llvm::Type::getInt64Ty(context()));

    auto function_argument_type =
        llvm::StructType::create(type_list, kEnterEventDataTypeName, false);

    if (function_argument_type == nullptr) {
      return StringError::create(
          "Failed to create the enter function parameter type");
    }

    function_argument_type =
        llvm::StructType::create(type_list, kExitEventDataTypeName, false);

    if (function_argument_type == nullptr) {
      return StringError::create(
          "Failed to create the exit function parameter type");
    }
  }

  // Define the EventData type; when dealing with tracepoints, we have to remove
  // the first 5 fields that are part of the header
  ebpf::Structure::iterator event_data_start_it;

  if (d->program_type == ProgramType::Tracepoint) {
    if (d->enter_structure.size() > 11) {
      return StringError::create("Invalid tracepoint event struct size");
    }

    event_data_start_it = std::next(d->enter_structure.begin(), 5U);

  } else {
    if (d->enter_structure.size() > 6) {
      return StringError::create("Invalid event struct size");
    }

    event_data_start_it = d->enter_structure.begin();
  }

  auto event_data_end_it = d->enter_structure.end();
  auto event_data_struct =
      ebpf::Structure(event_data_start_it, event_data_end_it);

  auto type_exp = importTracepointDescriptorStructure(event_data_struct,
                                                      kEventDataTypeName);

  if (!type_exp.succeeded()) {
    return type_exp.error();
  }

  auto event_data_type = type_exp.takeValue();

  // Define the event entry type
  type_list = {event_header, event_data_type};

  existing_type_ptr = module().getTypeByName(kEventEntryTypeName);
  if (existing_type_ptr != nullptr) {
    return StringError::create("A type named " + kEventEntryTypeName +
                               " is already defined");
  }

  auto event_entry_type =
      llvm::StructType::create(type_list, kEventEntryTypeName, true);

  if (event_entry_type == nullptr) {
    return StringError::create("Failed to create the event entry type");
  }

  // Generate the enter and exit functions
  auto event_function_exp = createSyscallEventFunction(
      &module(), "on_syscall_enter", kEnterEventDataTypeName);

  if (!event_function_exp.succeeded()) {
    return event_function_exp.error();
  }

  event_function_exp = createSyscallEventFunction(&module(), "on_syscall_exit",
                                                  kExitEventDataTypeName);

  if (!event_function_exp.succeeded()) {
    return event_function_exp.error();
  }

  // Now that we have defined the types, we can initialize the internal maps
  auto event_entry_type_size =
      ebpf::getLLVMStructureSize(event_entry_type, &module());

  ProgramResources program_resources;

  {
    auto event_map_exp =
        EventMap::create(event_entry_type_size, event_map_size);

    if (!event_map_exp.succeeded()) {
      return event_map_exp.error();
    }

    program_resources.event_map = event_map_exp.takeValue();
  }

  {
    auto stack_map_exp = StackMap::create(event_entry_type_size, 1U);

    if (!stack_map_exp.succeeded()) {
      return stack_map_exp.error();
    }

    program_resources.event_stack_map = stack_map_exp.takeValue();

    stack_map_exp = StackMap::create(d->buffer_storage.bufferSize(), 1U);

    if (!stack_map_exp.succeeded()) {
      return stack_map_exp.error();
    }

    program_resources.buffer_stack_map = stack_map_exp.takeValue();
  }

  return program_resources;
}

void BPFProgramWriter::setValue(const std::string &name, llvm::Value *value) {
  d->saved_value_map.insert({name, value});
}

void BPFProgramWriter::unsetValue(const std::string &name) {
  auto saved_value_it = d->saved_value_map.find(name);
  if (saved_value_it == d->saved_value_map.end()) {
    return;
  }

  d->saved_value_map.erase(saved_value_it);
}

void BPFProgramWriter::clearSavedValues() { d->saved_value_map.clear(); }

BPFProgramWriter::BPFProgramWriter(llvm::Module &module,
                                   IBufferStorage &buffer_storage,
                                   const ebpf::Structure &enter_structure,
                                   const ebpf::Structure &exit_structure,
                                   ProgramType program_type)
    : d(new PrivateData(module, buffer_storage)) {

  d->enter_structure = enter_structure;
  d->exit_structure = exit_structure;
  d->program_type = program_type;

  auto bpf_syscall_interface_exp =
      ebpf::BPFSyscallInterface::create(d->builder);

  if (!bpf_syscall_interface_exp.succeeded()) {
    throw bpf_syscall_interface_exp.error();
  }

  d->bpf_syscall_interface = bpf_syscall_interface_exp.takeValue();
}

StringErrorOr<llvm::Type *> BPFProgramWriter::importTracepointDescriptorType(
    const ebpf::StructureField &structure_field) {

  llvm::Type *output{nullptr};

  if (structure_field.type.find('*') == std::string::npos) {
    switch (structure_field.size) {
    case 1U:
      output = llvm::Type::getInt8Ty(context());
      break;

    case 2U:
      output = llvm::Type::getInt16Ty(context());
      break;

    case 4U:
      output = llvm::Type::getInt32Ty(context());
      break;

    case 8U:
      output = llvm::Type::getInt64Ty(context());
      break;

    default:
      break;
    }

  } else {
    output = llvm::Type::getInt8PtrTy(context());
  }

  if (output == nullptr) {
    return StringError::create("Unsupported tracepoint parameter type");
  }

  return output;
}

StringErrorOr<llvm::StructType *>
BPFProgramWriter::importTracepointDescriptorStructure(
    const ebpf::Structure &structure, const std::string &name) {

  auto output = module().getTypeByName(name);
  if (output != nullptr) {
    return StringError::create(
        "A type with the same name is already defined (" + name + ")");
  }

  std::vector<llvm::Type *> type_list;

  for (const auto &structure_field : structure) {
    auto type_exp = importTracepointDescriptorType(structure_field);

    if (!type_exp.succeeded()) {
      return type_exp.error();
    }

    type_list.push_back(type_exp.takeValue());
  }

  output = llvm::StructType::create(context(), type_list, name, false);

  if (output == nullptr) {
    return StringError::create("Failed to create the LLVM structure type");
  }

  return output;
}
} // namespace tob::ebpfpub
