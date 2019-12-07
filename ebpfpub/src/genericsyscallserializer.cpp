#include "genericsyscallserializer.h"

#include <unordered_set>

namespace ebpfpub {
namespace {
StringErrorOr<std::string>
bufferStorageEntryToString(std::uint64_t index, BufferStorage &buffer_storage) {
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

struct GenericSyscallSerializer::PrivateData final {
  ITracepointEvent::Structure enter_event_struct;
  std::unordered_set<std::string> string_parameter_list;
};

GenericSyscallSerializer::GenericSyscallSerializer() : d(new PrivateData) {}

GenericSyscallSerializer::~GenericSyscallSerializer() {}

const std::string &GenericSyscallSerializer::name() const {
  static const std::string kSerializerName{"generic"};
  return kSerializerName;
}

SuccessOrStringError
GenericSyscallSerializer::generate(const ITracepointEvent &enter_event,
                                   BPFProgramWriter &bpf_prog_writer) {

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

  // Take the event data
  auto &builder = bpf_prog_writer.builder();
  auto &context = bpf_prog_writer.context();

  d->enter_event_struct = enter_event.structure();

  auto event_data = builder.CreateGEP(
      event_entry, {builder.getInt32(0), builder.getInt32(1)});

  // As we already captured everything during the enter event, we only have to
  // deal with char pointers and ignore everything else
  // Note: we start from 5U in order to skip the function context header
  for (std::uint32_t source_index = 5U;
       source_index < d->enter_event_struct.size(); ++source_index) {

    const auto &syscall_param = d->enter_event_struct.at(source_index);

    std::size_t ptr_symbol_count = 0U;
    for (const auto &c : syscall_param.type) {
      if (c == '*') {
        ++ptr_symbol_count;
      }
    }

    if (ptr_symbol_count != 1U) {
      continue;
    }

    if (syscall_param.type.find("char") == std::string::npos) {
      continue;
    }

    d->string_parameter_list.insert(syscall_param.name);

    auto param_bb = llvm::BasicBlock::Create(
        context, "capture_string_" + syscall_param.name, exit_function);

    builder.CreateBr(param_bb);
    builder.SetInsertPoint(param_bb);

    // Read back the pointer value, and capture the string
    auto destination_index = source_index - 5U;

    auto memory_pointer = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(destination_index)});

    auto success_exp = bpf_prog_writer.captureString(memory_pointer);
    if (success_exp.failed()) {
      return success_exp.error();
    }
  }

  return {};
}

SuccessOrStringError
GenericSyscallSerializer::parseEvents(ISyscallTracepoint::Event &event,
                                      BufferReader &buffer_reader,
                                      BufferStorage &buffer_storage) {

  // Start from the 5th element, so we skip the context information
  for (std::uint32_t i = 5U; i < d->enter_event_struct.size(); ++i) {
    const auto &syscall_param = d->enter_event_struct.at(i);

    const auto &param_size = syscall_param.size;
    const auto &param_name = syscall_param.name;
    auto param_is_signed = syscall_param.is_signed;

    ISyscallTracepoint::Event::Integer integer;
    integer.is_signed = param_is_signed;

    switch (param_size) {
    case 1U: {
      integer.type = ISyscallTracepoint::Event::Integer::Type::Int8;
      integer.value = buffer_reader.u8();
      break;
    }

    case 2U: {
      integer.type = ISyscallTracepoint::Event::Integer::Type::Int16;
      integer.value = buffer_reader.u16();
      break;
    }

    case 4U: {
      integer.type = ISyscallTracepoint::Event::Integer::Type::Int32;
      integer.value = buffer_reader.u32();
      break;
    }

    case 8U: {
      integer.type = ISyscallTracepoint::Event::Integer::Type::Int64;
      integer.value = buffer_reader.u64();
      break;
    }

    default: {
      return StringError::create("Invalid type size: " +
                                 std::to_string(param_size));
    }
    }

    ISyscallTracepoint::Event::Variant event_value = {};

    if (d->string_parameter_list.count(param_name) > 0) {
      if ((integer.value >> 56) == 0xFF) {
        auto string_exp =
            bufferStorageEntryToString(integer.value, buffer_storage);

        if (string_exp.succeeded()) {
          event_value = string_exp.takeValue();
        } else {
          event_value = integer;
        }
      }

    } else {
      event_value = integer;
    }

    event.field_map.insert({param_name, std::move(event_value)});
  }

  return {};
}
} // namespace ebpfpub
