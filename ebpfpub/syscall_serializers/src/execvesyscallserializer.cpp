/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <iomanip>
#include <sstream>

#include <netinet/in.h>
#include <sys/un.h>

#include <ebpfpub/serializers/execvesyscallserializer.h>

#include <tob/ebpf/bpfmap.h>
#include <tob/ebpf/bpfsyscallinterface.h>

namespace tob::ebpfpub {
namespace {
using PerCpuArrayMap =
    tob::ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

const std::size_t kArgvParameterCount{32U};

StringErrorOr<std::string>
bufferStorageEntryToString(std::uint64_t index,
                           IBufferStorage &buffer_storage) {
  auto L_getStringLength =
      [](const std::vector<std::uint8_t> &buffer) -> std::size_t {
    auto buffer_ptr = buffer.data();

    std::size_t length = 0;
    while (length < buffer.size() && buffer_ptr[length] != '\x00') {
      ++length;
    }

    return length;
  };

  std::vector<std::uint8_t> buffer;

  auto buffer_storage_err = buffer_storage.getBuffer(buffer, index);
  if (!buffer_storage_err.succeeded()) {
    return StringError::create("Failed to acquire the buffer");
  }

  auto length = L_getStringLength(buffer);
  if (length == 0U) {
    return std::string();
  }

  std::string output;
  output.resize(length);

  std::memcpy(&output[0], buffer.data(), length);
  return output;
}
} // namespace

const std::string ExecveSyscallSerializer::name{"execve"};

struct ExecveSyscallSerializer::PrivateData final {
  int buffer_storage_fd{-1};
  PerCpuArrayMap::Ref argv_data_map;
};

ExecveSyscallSerializer::ExecveSyscallSerializer(IBufferStorage &buffer_storage)
    : d(new PrivateData) {
  d->buffer_storage_fd = buffer_storage.bufferMap();

  // Create the argv_data map
  auto map_size = kArgvParameterCount * 8U;
  if (map_size > buffer_storage.bufferSize()) {
    throw StringError::create("Invalid buffer size");
  }

  map_size = buffer_storage.bufferSize();

  auto argv_data_map_exp = PerCpuArrayMap::create(map_size, 1);
  if (!argv_data_map_exp.succeeded()) {
    throw argv_data_map_exp.error();
  }

  d->argv_data_map = argv_data_map_exp.takeValue();
}

ExecveSyscallSerializer::~ExecveSyscallSerializer() {}

const std::string &ExecveSyscallSerializer::getName() const { return name; }

const IFunctionSerializer::StageList &ExecveSyscallSerializer::stages() const {
  static const StageList kStageList = {Stage::Enter};
  return kStageList;
}

SuccessOrStringError
ExecveSyscallSerializer::generate(Stage stage,
                                  const ebpf::Structure &enter_structure,
                                  IBPFProgramWriter &bpf_prog_writer) {

  static_cast<void>(enter_structure);

  if (stage != Stage::Enter) {
    return StringError::create(
        "An unsupported serializer stage has been invoked");
  }

  // Take the event entry
  auto value_exp = bpf_prog_writer.value("event_entry");
  if (!value_exp.succeeded()) {
    return StringError::create("The event_entry value is not set");
  }

  auto event_entry = value_exp.takeValue();

  // Take the event data
  auto &builder = bpf_prog_writer.builder();

  auto event_data = builder.CreateGEP(
      event_entry, {builder.getInt32(0), builder.getInt32(1)});

  // Read back the filename pointer value, and capture the string
  auto memory_pointer =
      builder.CreateGEP(event_data, {builder.getInt32(0), builder.getInt32(0)});

  auto success_exp = bpf_prog_writer.captureString(memory_pointer);
  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Initialize the BPF syscall interface, so we can use it to read memory
  // pointers
  auto bpf_syscall_interface_exp = ebpf::BPFSyscallInterface::create(builder);
  if (!bpf_syscall_interface_exp.succeeded()) {
    return bpf_syscall_interface_exp.error();
  }

  auto bpf_syscall_interface = bpf_syscall_interface_exp.takeValue();

  // Get the enter function and then the context so we can create
  // new basic blocks
  auto enter_function_exp = bpf_prog_writer.getEnterFunction();

  if (!enter_function_exp.succeeded()) {
    return enter_function_exp.error();
  }

  auto enter_function = enter_function_exp.takeValue();
  auto &context = bpf_prog_writer.context();

  // Create a new structure type for the argv_data map
  std::vector<llvm::Type *> argv_data_members(kArgvParameterCount,
                                              builder.getInt8PtrTy());

  auto argv_data_type =
      llvm::StructType::create(argv_data_members, "ArgvData", true);

  // Get a pointer to the argv_data map using the type we just created
  auto map_entry_key_exp = bpf_prog_writer.value("scratch_space_32");
  if (!map_entry_key_exp.succeeded()) {
    return map_entry_key_exp.error();
  }

  auto map_entry_key = map_entry_key_exp.takeValue();
  builder.CreateStore(builder.getInt32(0U), map_entry_key);

  auto argv_data = bpf_syscall_interface->mapLookupElem(
      d->argv_data_map->fd(), map_entry_key, argv_data_type->getPointerTo());

  auto null_argv_data_ptr = llvm::Constant::getNullValue(argv_data->getType());

  auto check_argv_data_ptr_cond =
      builder.CreateICmpEQ(argv_data, null_argv_data_ptr);

  auto invalid_argv_data_ptr_bb = llvm::BasicBlock::Create(
      context, "invalid_argv_data_ptr", enter_function);

  auto valid_argv_data_ptr_bb =
      llvm::BasicBlock::Create(context, "valid_argv_data_ptr", enter_function);

  builder.CreateCondBr(check_argv_data_ptr_cond, invalid_argv_data_ptr_bb,
                       valid_argv_data_ptr_bb);

  builder.SetInsertPoint(invalid_argv_data_ptr_bb);
  builder.CreateRet(builder.getInt64(0));

  builder.SetInsertPoint(valid_argv_data_ptr_bb);

  // Reset the argv_data buffer
  for (std::uint32_t i = 0U; i < kArgvParameterCount; ++i) {
    auto element_ptr = builder.CreateGEP(
        argv_data, {builder.getInt32(0), builder.getInt32(i)});

    builder.CreateStore(llvm::Constant::getNullValue(builder.getInt8PtrTy()),
                        element_ptr);
  }

  // Read back the argv pointer value
  llvm::Value *argv{nullptr};

  {
    auto argv_ptr = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(1)});

    auto temp_argv = builder.CreateLoad(argv_ptr);
    argv = builder.CreateCast(llvm::Instruction::PtrToInt, temp_argv,
                              builder.getInt64Ty());
  }

  // Attempt to read kArgvParameterCount entries from the argv array
  auto argv_element_exp = bpf_prog_writer.value("scratch_space_64");
  if (!argv_element_exp.succeeded()) {
    return argv_element_exp.error();
  }

  auto argv_element = argv_element_exp.takeValue();

  auto emit_argv_data_bb =
      llvm::BasicBlock::Create(context, "emit_argv_data", enter_function);

  for (std::uint32_t i = 0U; i < kArgvParameterCount; ++i) {
    // Read the current argv[i] element
    auto argv_element_ptr = builder.CreateBinOp(llvm::Instruction::Add, argv,
                                                builder.getInt64(i * 8U));

    argv_element_ptr =
        builder.CreateCast(llvm::Instruction::IntToPtr, argv_element_ptr,
                           llvm::Type::getInt64PtrTy(context));

    auto probe_read_err = bpf_syscall_interface->probeRead(
        argv_element, builder.getInt32(8U), argv_element_ptr);

    auto probe_read_err_cond =
        builder.CreateICmpEQ(probe_read_err, builder.getInt64(0));

    auto continue_bb = llvm::BasicBlock::Create(
        context, "inspect_argv_" + std::to_string(i), enter_function);

    builder.CreateCondBr(probe_read_err_cond, continue_bb, emit_argv_data_bb);

    builder.SetInsertPoint(continue_bb);

    auto argv_element_value = builder.CreateLoad(argv_element);

    auto argv_value_cond = builder.CreateICmpEQ(
        argv_element_value,
        llvm::Constant::getNullValue(argv_element_value->getType()));

    continue_bb = llvm::BasicBlock::Create(
        context, "capture_argv_" + std::to_string(i), enter_function);

    builder.CreateCondBr(argv_value_cond, emit_argv_data_bb, continue_bb);

    builder.SetInsertPoint(continue_bb);

    // Store argv[1] inside the argv_data map
    auto argv_data_entry_ptr = builder.CreateGEP(
        argv_data, {builder.getInt32(0), builder.getInt32(i)});

    auto argv_element_value_casted =
        builder.CreateCast(llvm::Instruction::IntToPtr, argv_element_value,
                           builder.getInt8PtrTy());

    builder.CreateStore(argv_element_value_casted, argv_data_entry_ptr);

    bpf_prog_writer.captureString(argv_data_entry_ptr);
  }

  builder.CreateBr(emit_argv_data_bb);
  builder.SetInsertPoint(emit_argv_data_bb);

  // Store the argv_data inside the buffer storage
  auto buffer_storage_index_value_exp =
      bpf_prog_writer.generateBufferStorageIndex();

  if (!buffer_storage_index_value_exp.succeeded()) {
    return buffer_storage_index_value_exp.error();
  }

  auto buffer_storage_index_value = buffer_storage_index_value_exp.takeValue();

  auto buffer_storage_index_exp = bpf_prog_writer.value("scratch_space_32");
  if (!buffer_storage_index_exp.succeeded()) {
    return buffer_storage_index_exp.error();
  }

  auto buffer_storage_index = buffer_storage_index_exp.takeValue();

  builder.CreateStore(buffer_storage_index_value, buffer_storage_index);

  bpf_syscall_interface->mapUpdateElem(d->buffer_storage_fd, argv_data,
                                       buffer_storage_index, BPF_ANY);

  // Store the buffer storage index inside the event data
  auto marked_buffer_storage_index_exp =
      bpf_prog_writer.markBufferStorageIndex(buffer_storage_index_value);

  if (!marked_buffer_storage_index_exp.succeeded()) {
    return marked_buffer_storage_index_exp.error();
  }

  auto marked_buffer_storage_index =
      marked_buffer_storage_index_exp.takeValue();

  marked_buffer_storage_index =
      builder.CreateCast(llvm::Instruction::IntToPtr,
                         marked_buffer_storage_index, builder.getInt8PtrTy());

  auto argv_ptr =
      builder.CreateGEP(event_data, {builder.getInt32(0), builder.getInt32(1)});

  builder.CreateStore(marked_buffer_storage_index, argv_ptr);

  return {};
}

SuccessOrStringError
ExecveSyscallSerializer::parseEvents(IFunctionSerializer::Event &event,
                                     IBufferReader &buffer_reader,
                                     IBufferStorage &buffer_storage) {

  // Get the filename ptr
  IFunctionSerializer::Event::Integer event_field;
  event_field.is_signed = false;
  event_field.type = IFunctionSerializer::Event::Integer::Type::Int64;
  event_field.value = buffer_reader.u64();

  IFunctionSerializer::Event::Variant event_value = {};

  if ((event_field.value >> 56) == 0xFF) {
    auto string_exp =
        bufferStorageEntryToString(event_field.value, buffer_storage);

    if (string_exp.succeeded()) {
      event_value = string_exp.takeValue();
    } else {
      event_value = event_field;
    }

  } else {
    event_value = event_field;
  }

  event.field_map.insert({"filename", std::move(event_value)});

  // Get the argv parameters
  event_field = {};
  event_field.is_signed = false;
  event_field.type = IFunctionSerializer::Event::Integer::Type::Int64;
  event_field.value = buffer_reader.u64();

  event_value = {};

  if ((event_field.value >> 56) == 0xFF) {
    std::vector<std::uint8_t> buffer;
    auto buffer_storage_err =
        buffer_storage.getBuffer(buffer, event_field.value);

    if (buffer_storage_err.succeeded()) {
      std::stringstream parameter_list;

      bool terminator_found{false};
      bool add_separator{false};

      for (std::size_t i = 0U; i < kArgvParameterCount; ++i) {
        auto ptr = buffer.data() + (i * 8U);

        std::uint64_t buffer_index;
        std::memcpy(&buffer_index, ptr, sizeof(buffer_index));

        if (buffer_index == 0) {
          terminator_found = true;
          break;
        }

        if ((buffer_index >> 56) != 0xFF) {
          break;
        }

        auto string_exp =
            bufferStorageEntryToString(buffer_index, buffer_storage);

        if (add_separator) {
          parameter_list << " ";
        }

        if (string_exp.succeeded()) {
          auto string_value = string_exp.takeValue();
          parameter_list << "\"" << string_value << "\"";

        } else {
          parameter_list << "<ERROR_CAPTURING_PARAM>";
        }

        add_separator = true;
      }

      if (!terminator_found) {
        if (add_separator) {
          parameter_list << " ";
        }

        parameter_list << "...";
      }

      event_value = parameter_list.str();

    } else {
      event_value = event_field;
    }

  } else {
    event_value = event_field;
  }

  event.field_map.insert({"argv", std::move(event_value)});

  return {};
}
} // namespace tob::ebpfpub
