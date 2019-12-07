#include "connectsyscallserializer.h"

#include <iomanip>

#include <netinet/in.h>
#include <sys/un.h>

namespace ebpfpub {
namespace {
std::uint32_t kAddressStructSizeLimit{512U};
}

struct ConnectSyscallSerializer::PrivateData final {
  ITracepointEvent::Structure enter_event_struct;
};

ConnectSyscallSerializer::ConnectSyscallSerializer() : d(new PrivateData) {}

ConnectSyscallSerializer::~ConnectSyscallSerializer() {}

const std::string &ConnectSyscallSerializer::name() const {
  static const std::string kSerializerName{"connect"};
  return kSerializerName;
}

SuccessOrStringError
ConnectSyscallSerializer::generate(const ITracepointEvent &enter_event,
                                   BPFProgramWriter &bpf_prog_writer) {

  // Save the enter event structure
  d->enter_event_struct = enter_event.structure();

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

  // Read back the `socklen_t address_len` value
  auto address_len_ptr = builder.CreateGEP(
      event_data, {builder.getInt32(0), builder.getInt32(2U)});

  auto address_len = builder.CreateLoad(address_len_ptr);

  // Limit the amount of bytes that can be specified inside the size field
  llvm::Value *address_len_limit{nullptr};
  auto address_len_type_size = d->enter_event_struct.at(5U + 2U).size;

  if (address_len_type_size == 4U) {
    address_len_limit = builder.getInt32(kAddressStructSizeLimit);

  } else if (address_len_type_size == 8U) {
    address_len_limit = builder.getInt64(kAddressStructSizeLimit);

  } else {
    StringError::create("Invalid `address_len` type size");
  }

  auto address_len_condition =
      builder.CreateICmpUGT(address_len, builder.getInt64(256U));

  auto invalid_address_len_bb =
      llvm::BasicBlock::Create(context, "invalid_address_len", exit_function);

  auto capture_address_buffer_bb = llvm::BasicBlock::Create(
      context, "capture_address_buffer", exit_function);

  builder.CreateCondBr(address_len_condition, invalid_address_len_bb,
                       capture_address_buffer_bb);

  builder.SetInsertPoint(invalid_address_len_bb);
  builder.CreateRet(builder.getInt64(0));

  builder.SetInsertPoint(capture_address_buffer_bb);

  // Capture the sockaddr buffer
  auto sockaddr_ptr = builder.CreateGEP(
      event_data, {builder.getInt32(0), builder.getInt32(1U)});

  auto success_exp = bpf_prog_writer.captureBuffer(sockaddr_ptr, address_len);
  if (success_exp.failed()) {
    return success_exp.error();
  }

  return {};
}

SuccessOrStringError
ConnectSyscallSerializer::parseEvents(ISyscallTracepoint::Event &event,
                                      BufferReader &buffer_reader,
                                      BufferStorage &buffer_storage) {

  // fd
  const auto &fd_field = d->enter_event_struct.at(5U + 0U);

  ISyscallTracepoint::Event::Integer fd_integer;
  fd_integer.is_signed = fd_field.is_signed;

  switch (fd_field.size) {
  case 4U: {
    fd_integer.type = ISyscallTracepoint::Event::Integer::Type::Int32;
    fd_integer.value = buffer_reader.u32();
    break;
  }

  case 8U: {
    fd_integer.type = ISyscallTracepoint::Event::Integer::Type::Int64;
    fd_integer.value = buffer_reader.u64();
    break;
  }

  default: {
    return StringError::create("Invalid type size: " +
                               std::to_string(fd_field.size));
  }
  }

  // sockaddr buffer ptr
  ISyscallTracepoint::Event::Integer sockaddr_integer;
  sockaddr_integer.type = ISyscallTracepoint::Event::Integer::Type::Int64;
  sockaddr_integer.value = buffer_reader.u64();

  // addrlen
  auto addrlen_field = d->enter_event_struct.at(5U + 2U);

  ISyscallTracepoint::Event::Integer addrlen_integer;
  addrlen_integer.is_signed = addrlen_field.is_signed;

  switch (addrlen_field.size) {
  case 4U: {
    addrlen_integer.type = ISyscallTracepoint::Event::Integer::Type::Int32;
    addrlen_integer.value = buffer_reader.u32();
    break;
  }

  case 8U: {
    addrlen_integer.type = ISyscallTracepoint::Event::Integer::Type::Int64;
    addrlen_integer.value = buffer_reader.u64();
    break;
  }

  default: {
    return StringError::create("Invalid type size: " +
                               std::to_string(addrlen_field.size));
  }
  }

  // Attempt to get the buffer contents
  if ((sockaddr_integer.value >> 56) == 0xFF) {
    std::vector<std::uint8_t> sockdaddr_buffer;

    auto buffer_storage_err =
        buffer_storage.getBuffer(sockdaddr_buffer, sockaddr_integer.value);

    sockdaddr_buffer.resize(addrlen_integer.value);

    if (buffer_storage_err.succeeded()) {
      if (sockdaddr_buffer.size() == sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr {};
        std::memcpy(&addr, sockdaddr_buffer.data(), sizeof(addr));

        auto port = static_cast<std::int64_t>(htons(addr.sin_port));

        auto numeric_address = htonl(addr.sin_addr.s_addr);

        std::uint8_t numeric_address_bytes[4];
        std::memcpy(numeric_address_bytes, &numeric_address,
                    sizeof(numeric_address));

        std::string string_address;
        for (std::size_t i = 0U; i < 4U; ++i) {
          string_address += std::to_string(numeric_address_bytes[i]);

          if (i < 3) {
            string_address.push_back('.');
          }
        }

        string_address += ", port " + std::to_string(port);

        event.field_map.insert({"sockaddr", string_address});

      } else if (sockdaddr_buffer.size() == sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 addr {};
        std::memcpy(&addr, sockdaddr_buffer.data(), sizeof(addr));

        auto port = static_cast<std::int64_t>(htons(addr.sin6_port));

        std::stringstream str_stream;
        for (std::size_t i = 0U; i < 16U; ++i) {
          str_stream << std::hex << std::setw(2) << std::setfill('0')
                     << static_cast<int>(addr.sin6_addr.s6_addr[i]);

          if (i < 15U) {
            str_stream << ":";
          }
        }

        str_stream << ", port " << std::to_string(port);

        event.field_map.insert({"sockaddr", str_stream.str()});

      } else if (sockdaddr_buffer.size() == sizeof(struct sockaddr_un)) {
        struct sockaddr_un addr {};
        std::memcpy(&addr, sockdaddr_buffer.data(), sizeof(addr));

        event.field_map.insert({"sockaddr", addr.sun_path});

      } else {
        event.field_map.insert({"sockaddr", sockdaddr_buffer});
      }
    }
  }

  event.field_map.insert({"fd", std::move(fd_integer)});
  event.field_map.insert({"addrlen", std::move(addrlen_integer)});

  if (event.field_map.count("sockaddr") == 0) {
    event.field_map.insert({"sockaddr", std::move(sockaddr_integer)});
  }

  return {};
}
} // namespace ebpfpub
