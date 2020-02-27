/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "readlineserializer.h"

#include <unordered_set>

namespace tob::ebpfpub {
namespace {
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

const std::string ReadlineSerializer::name{"readline"};

StringErrorOr<IFunctionSerializer::Ref> ReadlineSerializer::create() {
  try {
    return Ref(new ReadlineSerializer());

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

ReadlineSerializer::~ReadlineSerializer() {}

const std::string &ReadlineSerializer::getName() const { return name; }

const IFunctionSerializer::StageList &ReadlineSerializer::stages() const {
  static const StageList kStageList{Stage::Exit};
  return kStageList;
}

SuccessOrStringError
ReadlineSerializer::generate(Stage stage,
                             const ebpf::Structure &enter_structure,
                             IBPFProgramWriter &bpf_prog_writer) {

  if (stage != Stage::Exit) {
    return {};
  }

  // Take the event entry
  auto value_exp = bpf_prog_writer.value("event_entry");
  if (!value_exp.succeeded()) {
    return StringError::create("The event_entry value is not set");
  }

  auto event_entry = value_exp.takeValue();

  // Take the function ptr
  auto exit_function_exp = bpf_prog_writer.getExitFunction();
  if (!exit_function_exp.succeeded()) {
    return exit_function_exp.error();
  }

  auto exit_function = exit_function_exp.takeValue();

  // Take the event data structure
  auto &builder = bpf_prog_writer.builder();
  auto &context = bpf_prog_writer.context();

  auto event_data = builder.CreateGEP(
      event_entry, {builder.getInt32(0), builder.getInt32(1)});

  // Take the event header structure
  auto event_header = builder.CreateGEP(
      event_entry, {builder.getInt32(0), builder.getInt32(0)});

  // Capture the 'prompt' parameter
  auto named_basic_block =
      llvm::BasicBlock::Create(context, "capture_string_prompt", exit_function);

  builder.CreateBr(named_basic_block);
  builder.SetInsertPoint(named_basic_block);

  auto memory_pointer =
      builder.CreateGEP(event_data, {builder.getInt32(0), builder.getInt32(0)});

  auto success_exp = bpf_prog_writer.captureString(memory_pointer);
  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Capture the returned pointer
  named_basic_block = llvm::BasicBlock::Create(
      context, "capture_string_return_value", exit_function);

  builder.CreateBr(named_basic_block);
  builder.SetInsertPoint(named_basic_block);

  memory_pointer = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(5)});

  success_exp = bpf_prog_writer.captureString(memory_pointer);
  if (success_exp.failed()) {
    return success_exp.error();
  }

  return {};
}

SuccessOrStringError
ReadlineSerializer::parseEvents(IFunctionSerializer::Event &event,
                                IBufferReader &buffer_reader,
                                IBufferStorage &buffer_storage) {

  // Get the 'prompt' parameter
  IFunctionSerializer::Event::Variant event_value = {};

  IFunctionSerializer::Event::Integer prompt_string_ptr;
  prompt_string_ptr.type = IFunctionSerializer::Event::Integer::Type::Int64;
  prompt_string_ptr.is_signed = false;
  prompt_string_ptr.value = buffer_reader.u64();

  bool save_raw_prompt_str_pointer{true};
  if ((prompt_string_ptr.value >> 56) == 0xFF) {
    auto string_exp =
        bufferStorageEntryToString(prompt_string_ptr.value, buffer_storage);

    if (string_exp.succeeded()) {
      event_value = string_exp.takeValue();
      save_raw_prompt_str_pointer = false;
    }
  }

  if (save_raw_prompt_str_pointer) {
    event_value = prompt_string_ptr;
  }

  event.field_map.insert({"prompt", std::move(event_value)});

  // Get the returned string
  if ((event.header.exit_code >> 56) == 0xFF) {
    auto string_exp =
        bufferStorageEntryToString(event.header.exit_code, buffer_storage);

    if (string_exp.succeeded()) {
      event_value = string_exp.takeValue();
      event.field_map.insert({"exit_code", std::move(event_value)});
    }
  }

  return {};
}

ReadlineSerializer::ReadlineSerializer() {}
} // namespace tob::ebpfpub
