/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "bpfprogramwriter.h"
#include "llvm_utils.h"

#include <linux/bpf.h>

namespace ebpfpub {
namespace {
using EventMap = BPFMap<BPF_MAP_TYPE_HASH, std::uint64_t>;
using StackMap = BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

const std::string kEnterEventDataTypeName{"EnterEventData"};
const std::string kExitEventDataTypeName{"ExitEventData"};
const std::string kEventHeaderTypeName{"EventHeader"};
const std::string kEvenDataTypeName{"EventData"};
const std::string kEventEntryTypeName{"EventEntry"};
} // namespace

struct BPFProgramWriter::PrivateData final {
  PrivateData(llvm::Module &module_, BufferStorage &buffer_storage_,
              const ITracepointEvent &enter_event_,
              const ITracepointEvent &exit_event_)
      : module(module_), context(module_.getContext()), builder(context),
        buffer_storage(buffer_storage_), enter_event(enter_event_),
        exit_event(exit_event_) {}

  llvm::Module &module;
  llvm::LLVMContext &context;

  llvm::IRBuilder<> builder;

  BufferStorage &buffer_storage;

  const ITracepointEvent &enter_event;
  const ITracepointEvent &exit_event;

  std::unordered_map<std::string, llvm::Value *> saved_value_map;
};

StringErrorOr<BPFProgramWriter::Ref>
BPFProgramWriter::create(llvm::Module &module, BufferStorage &buffer_storage,
                         const ITracepointEvent &enter_event,
                         const ITracepointEvent &exit_event) {
  try {
    return Ref(
        new BPFProgramWriter(module, buffer_storage, enter_event, exit_event));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

BPFProgramWriter::~BPFProgramWriter() {}

llvm::IRBuilder<> &BPFProgramWriter::builder() { return d->builder; }

llvm::Module &BPFProgramWriter::module() { return d->module; }

llvm::LLVMContext &BPFProgramWriter::context() { return d->context; }

StringErrorOr<BPFProgramResources>
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

  // Import the types from the tracepoint format descriptors
  auto type_exp = importTracepointEventStructure(d->enter_event.structure(),
                                                 kEnterEventDataTypeName);

  if (!type_exp.succeeded()) {
    return type_exp.error();
  }

  type_exp = importTracepointEventStructure(d->exit_event.structure(),
                                            kExitEventDataTypeName);

  if (!type_exp.succeeded()) {
    return type_exp.error();
  }

  // Define the EventData type; this is a stripped version of the EnterEventData
  auto event_data_start_it = std::next(d->enter_event.structure().begin(), 5U);

  auto event_data_end_it = d->enter_event.structure().end();

  auto event_data_struct =
      ITracepointEvent::Structure(event_data_start_it, event_data_end_it);

  type_exp =
      importTracepointEventStructure(event_data_struct, kEvenDataTypeName);

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
      getLLVMStructureSize(event_entry_type, &module());

  EventMap::Ref event_map;
  StackMap::Ref event_stack_map;
  StackMap::Ref buffer_stack_map;

  {
    auto event_map_exp =
        EventMap::create(event_entry_type_size, event_map_size);

    if (!event_map_exp.succeeded()) {
      return event_map_exp.error();
    }

    event_map = event_map_exp.takeValue();
  }

  {
    auto stack_map_exp = StackMap::create(event_entry_type_size, 1U);

    if (!stack_map_exp.succeeded()) {
      return stack_map_exp.error();
    }

    event_stack_map = stack_map_exp.takeValue();

    stack_map_exp = StackMap::create(d->buffer_storage.bufferSize(), 1U);

    if (!stack_map_exp.succeeded()) {
      return stack_map_exp.error();
    }

    buffer_stack_map = stack_map_exp.takeValue();
  }

  return BPFProgramResources(std::move(event_stack_map),
                             std::move(buffer_stack_map), std::move(event_map));
}

StringErrorOr<llvm::Function *> BPFProgramWriter::getEnterFunction() {
  auto function = module().getFunction("on_syscall_enter");
  if (function == nullptr) {
    return StringError::create("The program has not been initialized");
  }

  return function;
}

StringErrorOr<llvm::Function *> BPFProgramWriter::getExitFunction() {
  auto function = module().getFunction("on_syscall_exit");
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

StringErrorOr<llvm::Value *> BPFProgramWriter::value(const std::string &name) {
  auto saved_value_it = d->saved_value_map.find(name);
  if (saved_value_it == d->saved_value_map.end()) {
    return StringError::create("The specified value was not found");
  }

  return saved_value_it->second;
}

void BPFProgramWriter::clearSavedValues() { d->saved_value_map.clear(); }

llvm::Value *BPFProgramWriter::bpf_get_current_pid_tgid() {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),
    {},
    false
  );
  // clang-format on

  auto function = d->builder.CreateIntToPtr(
      d->builder.getInt64(BPF_FUNC_get_current_pid_tgid),
      llvm::PointerType::getUnqual(function_type));

  return d->builder.CreateCall(function);
}

llvm::Value *BPFProgramWriter::bpf_ktime_get_ns() {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),
    {},
    false
  );
  // clang-format on

  auto function =
      d->builder.CreateIntToPtr(d->builder.getInt64(BPF_FUNC_ktime_get_ns),
                                llvm::PointerType::getUnqual(function_type));

  return d->builder.CreateCall(function);
}

llvm::Value *BPFProgramWriter::bpf_get_current_uid_gid() {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),
    {},
    false
  );
  // clang-format on

  auto function = d->builder.CreateIntToPtr(
      d->builder.getInt64(BPF_FUNC_get_current_uid_gid),
      llvm::PointerType::getUnqual(function_type));

  return d->builder.CreateCall(function);
}

llvm::Value *BPFProgramWriter::bpf_get_smp_processor_id() {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt32Ty(d->context),
    {},
    false
  );
  // clang-format on

  auto function = d->builder.CreateIntToPtr(
      d->builder.getInt64(BPF_FUNC_get_smp_processor_id),
      llvm::PointerType::getUnqual(function_type));

  return d->builder.CreateCall(function);
}

llvm::Value *BPFProgramWriter::bpf_map_lookup_elem(int map_fd, llvm::Value *key,
                                                   llvm::Type *type) {

  // clang-format off
  auto function_type = llvm::FunctionType::get(
    type,

    {
      // Map address
      llvm::Type::getInt64PtrTy(context()),

      // key address
      key->getType()
    },

    false
  );
  // clang-format on

  auto function =
      d->builder.CreateIntToPtr(builder().getInt64(BPF_FUNC_map_lookup_elem),
                                llvm::PointerType::getUnqual(function_type));

  auto map_ptr_address_value = bpf_pseudo_map_fd(map_fd);

  return d->builder.CreateCall(function, {map_ptr_address_value, key});
}

void BPFProgramWriter::bpf_map_update_elem(int map_fd, llvm::Value *value,
                                           llvm::Value *key, int flags) {
  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),

    {
      // Map address
      llvm::Type::getInt64PtrTy(d->context),

      // key address
      key->getType(),

      // value address
      value->getType(),

      // flags
      llvm::Type::getInt64Ty(d->context)
    },

    false
  );
  // clang-format on

  auto function =
      d->builder.CreateIntToPtr(d->builder.getInt64(BPF_FUNC_map_update_elem),
                                llvm::PointerType::getUnqual(function_type));

  auto map_ptr_address_value = bpf_pseudo_map_fd(map_fd);

  d->builder.CreateCall(
      function, {map_ptr_address_value, key, value,
                 d->builder.getInt64(static_cast<std::uint32_t>(flags))});
}

llvm::Value *BPFProgramWriter::bpf_probe_read_str(llvm::Value *dest,
                                                  std::size_t size,
                                                  llvm::Value *src) {

  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),

    {
      // Destination address
      llvm::Type::getInt8PtrTy(d->context),

      // Size
      llvm::Type::getInt32Ty(d->context),

      // Source address
      llvm::Type::getInt8PtrTy(d->context),
    },

    false
  );
  // clang-format on

  auto function =
      d->builder.CreateIntToPtr(d->builder.getInt64(BPF_FUNC_probe_read_str),
                                llvm::PointerType::getUnqual(function_type));

  return d->builder.CreateCall(
      function,
      {dest, d->builder.getInt32(static_cast<std::uint32_t>(size)), src});
}

llvm::Value *BPFProgramWriter::bpf_probe_read(llvm::Value *dest,
                                              llvm::Value *size,
                                              llvm::Value *src) {

  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(d->context),

    {
      // Destination address
      llvm::Type::getInt8PtrTy(d->context),

      // Size
      size->getType(),

      // Source address
      llvm::Type::getInt8PtrTy(d->context),
    },

    false
  );
  // clang-format on

  auto function =
      d->builder.CreateIntToPtr(d->builder.getInt64(BPF_FUNC_probe_read),
                                llvm::PointerType::getUnqual(function_type));

  return d->builder.CreateCall(function, {dest, size, src});
}

SuccessOrStringError
BPFProgramWriter::bpf_perf_event_output(int map_fd, std::uint64_t flags,
                                        llvm::Value *data_ptr,
                                        std::uint32_t data_size) {

  auto &llvm_context = d->context;
  auto &builder = d->builder;

  // Get the current function
  auto current_block = builder.GetInsertBlock();
  if (current_block == nullptr) {
    return StringError::create("No active basic block");
  }

  auto current_function = current_block->getParent();
  if (current_function == nullptr) {
    return StringError::create("No active function");
  }

  // The first parameter for this syscall is the context; in our case, it's the
  // function argument
  auto context_value = current_function->arg_begin();
  auto context_type = context_value->getType();

  // clang-format off
  auto function_type = llvm::FunctionType::get(
    llvm::Type::getInt64Ty(llvm_context),

    {
      // Context
      context_type,

      // Map address
      llvm::Type::getInt64PtrTy(llvm_context),

      // Flags
      llvm::Type::getInt64Ty(llvm_context),

      // Data pointer
      data_ptr->getType(),

      // Data size
      llvm::Type::getInt64Ty(llvm_context)
    },

    false
  );
  // clang-format on

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_perf_event_output),
                             llvm::PointerType::getUnqual(function_type));

  auto map_ptr_address_value = bpf_pseudo_map_fd(map_fd);

  // clang-format off
  builder.CreateCall(
    function,
    
    {
      context_value,
      map_ptr_address_value,
      builder.getInt64(flags),
      data_ptr,
      builder.getInt64(static_cast<std::uint64_t>(data_size))
    }
  );
  // clang-format on

  return {};
}

BPFProgramWriter::BPFProgramWriter(llvm::Module &module,
                                   BufferStorage &buffer_storage,
                                   const ITracepointEvent &enter_event,
                                   const ITracepointEvent &exit_event)
    : d(new PrivateData(module, buffer_storage, enter_event, exit_event)) {}

llvm::Function *BPFProgramWriter::getPseudoInstrinsic() {
  llvm::Function *pseudo_function = module().getFunction("llvm.bpf.pseudo");

  if (pseudo_function == nullptr) {
    // clang-format off
    auto pseudo_function_type = llvm::FunctionType::get(
      llvm::Type::getInt64Ty(d->context),

      {
        llvm::Type::getInt64Ty(d->context),
        llvm::Type::getInt64Ty(d->context)
      },

      false
    );
    // clang-format on

    pseudo_function = llvm::Function::Create(pseudo_function_type,
                                             llvm::GlobalValue::ExternalLinkage,
                                             "llvm.bpf.pseudo", module());
  }

  return pseudo_function;
}

llvm::Value *BPFProgramWriter::bpf_pseudo_map_fd(int fd) {
  auto pseudo_function = getPseudoInstrinsic();
  auto map_fd = static_cast<std::uint64_t>(fd);

  // clang-format off
  auto map_integer_address_value = d->builder.CreateCall(
    pseudo_function,

    {
      d->builder.getInt64(BPF_PSEUDO_MAP_FD),
      d->builder.getInt64(map_fd)
    }
  );
  // clang-format on

  return d->builder.CreateIntToPtr(map_integer_address_value,
                                   llvm::Type::getInt64PtrTy(d->context));
}

StringErrorOr<llvm::Type *> BPFProgramWriter::importTracepointEventType(
    const ITracepointEvent::StructureField &structure_field) {
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
BPFProgramWriter::importTracepointEventStructure(
    const ITracepointEvent::Structure &structure, const std::string &name) {

  auto output = module().getTypeByName(name);
  if (output != nullptr) {
    return StringError::create(
        "A type with the same name is already defined (" + name + ")");
  }

  std::vector<llvm::Type *> type_list;

  for (const auto &structure_field : structure) {
    auto type_exp = importTracepointEventType(structure_field);

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
    auto current_processor_id = bpf_get_smp_processor_id();

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

  auto read_error = bpf_probe_read_str(
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

  bpf_map_update_elem(buffer_storage_fd, buffer_storage_stack,
                      buffer_storage_entry_key, BPF_ANY);

  // Update the string pointer
  auto marked_index_exp = markBufferStorageIndex(buffer_storage_index);

  if (!marked_index_exp.succeeded()) {
    return marked_index_exp.error();
  }

  auto marked_index = marked_index_exp.takeValue();

  marked_index =
      builder().CreateIntToPtr(marked_index, builder().getInt8PtrTy());

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

  auto read_error =
      bpf_probe_read(buffer_storage_stack, buffer_size, pointer_value);

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

  bpf_map_update_elem(buffer_storage_fd, buffer_storage_stack,
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
} // namespace ebpfpub
