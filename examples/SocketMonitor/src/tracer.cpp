/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "tracer.h"

#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/iperfeventreader.h>

#include <tob/ebpf/perfeventarray.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
const std::vector<std::string> kSyscallNameList = {
    "connect",
    "bind",
    "accept",
    "accept4",
};

// Custom parameter lists that only dump the filename string and uses
// integers for everything else

// clang-format off
tob::ebpfpub::IFunctionTracer::ParameterList kExecveParameterList = {
  {
    "filename",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    {}
  },

  {
    "argv",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "envp",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  }
};
// clang-format on

// clang-format off
tob::ebpfpub::IFunctionTracer::ParameterList kExecveatParameterList = {
  {
    "fd",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "filename",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    {}
  },

  {
    "argv",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "envp",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  },

  {
    "flags",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    8U
  }
};
// clang-format on

void generateHeaderData(Model::Row &row,
                        const tob::ebpfpub::IFunctionTracer::Event &event) {
  row.timestamp = event.header.timestamp;
  row.thread_id = event.header.thread_id;
  row.process_id = event.header.process_id;
  row.user_id = event.header.user_id;
  row.group_id = event.header.group_id;
  row.cgroup_id = event.header.cgroup_id;
  row.exit_code = event.header.exit_code;
  row.syscall_name = event.name;
}

void parseSockaddrStructure(
    std::string &address,
    const tob::ebpfpub::IFunctionTracer::Event::Field::Buffer &buffer) {

  sa_family_t sa_family{0U};
  std::memcpy(&sa_family, buffer.data(), sizeof(sa_family));

  std::stringstream output;

  switch (sa_family) {
  case AF_UNSPEC:
  case AF_INET: {
    output << "AF_INET=";

    struct sockaddr_in temp = {};
    std::memcpy(&temp, buffer.data(), sizeof(temp));

    std::uint8_t address_parts[4U] = {};
    std::memcpy(address_parts, &temp.sin_addr.s_addr, sizeof(address_parts));

    output << static_cast<int>(address_parts[0]) << "."
           << static_cast<int>(address_parts[1]) << "."
           << static_cast<int>(address_parts[2]) << "."
           << static_cast<int>(address_parts[3]);

    output << ":" << htons(temp.sin_port);
    break;
  }

  case AF_UNIX: {
    output << "AF_UNIX=";

    struct sockaddr_un temp = {};
    std::memcpy(&temp, buffer.data(), sizeof(temp));

    output << temp.sun_path;
    break;
  }

  default: {
    output << "unhandled_sa_family_t_value";
  }
  }

  address = output.str();
}
} // namespace

struct Tracer::PrivateData final {
  tob::ebpfpub::IBufferStorage::Ref buffer_storage;
  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

  std::unique_ptr<std::thread> event_thread;
  std::atomic_bool terminate_event_thread{false};

  Model::RowList row_list;
  std::mutex row_list_mutex;

  std::uint64_t connect_identifier{0U};
  std::uint64_t bind_identifier{0U};
  std::uint64_t accept_identifier{0U};
  std::uint64_t accept4_identifier{0U};
  std::uint64_t execve_identifier{0U};
  std::uint64_t execveat_identifier{0U};

  std::unordered_map<pid_t, std::string> process_id_map;
};

Tracer::Tracer() : d(new PrivateData) {
  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(1024, 1024);
  if (!buffer_storage_exp.succeeded()) {
    throw std::runtime_error("Failed to create the buffer storage: " +
                             buffer_storage_exp.error().message());
  }

  d->buffer_storage = buffer_storage_exp.takeValue();

  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(12);
  if (!perf_event_array_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event array: " +
                             perf_event_array_exp.error().message());
  }

  d->perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*d->perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  d->perf_event_reader = perf_event_reader_exp.takeValue();

  for (const auto &syscall_name : kSyscallNameList) {
    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            syscall_name, *d->buffer_storage.get(), *d->perf_event_array.get(),
            2048);

    if (!function_tracer_exp.succeeded()) {
      throw std::runtime_error("Failed to create the function tracer: " +
                               function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();

    if (syscall_name == "connect") {
      d->connect_identifier = function_tracer->eventIdentifier();

    } else if (syscall_name == "bind") {
      d->bind_identifier = function_tracer->eventIdentifier();

    } else if (syscall_name == "accept") {
      d->accept_identifier = function_tracer->eventIdentifier();

    } else if (syscall_name == "accept4") {
      d->accept4_identifier = function_tracer->eventIdentifier();
    }

    d->perf_event_reader->insert(std::move(function_tracer));
  }

  // Add two additional tracers for execve and execveat, using custom parameter
  // lists that ignore everything except the executable path
  auto function_tracer_exp =
      tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
          "execve", kExecveParameterList, *d->buffer_storage.get(),
          *d->perf_event_array.get(), 2048);

  if (!function_tracer_exp.succeeded()) {
    throw std::runtime_error(function_tracer_exp.error().message());
  }

  auto function_tracer = function_tracer_exp.takeValue();
  d->execve_identifier = function_tracer->eventIdentifier();
  d->perf_event_reader->insert(std::move(function_tracer));

  function_tracer_exp =
      tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
          "execveat", kExecveatParameterList, *d->buffer_storage.get(),
          *d->perf_event_array.get(), 2048);

  if (!function_tracer_exp.succeeded()) {
    throw std::runtime_error(function_tracer_exp.error().message());
  }

  function_tracer = function_tracer_exp.takeValue();
  d->execveat_identifier = function_tracer->eventIdentifier();
  d->perf_event_reader->insert(std::move(function_tracer));

  d->event_thread = std::make_unique<std::thread>(&Tracer::eventThread, this);
}

Tracer::~Tracer() {
  d->terminate_event_thread = true;
  d->event_thread->join();
}

Model::RowList Tracer::getRowList() const {
  Model::RowList row_list;

  {
    std::lock_guard<std::mutex> lock(d->row_list_mutex);

    row_list = std::move(d->row_list);
    d->row_list = {};
  }

  return row_list;
}

void Tracer::eventThread() {
  while (!d->terminate_event_thread) {
    d->perf_event_reader->exec(
        std::chrono::seconds(1U),

        [&](const tob::ebpfpub::IFunctionTracer::EventList &event_list,
            const tob::ebpfpub::IPerfEventReader::ErrorCounters &) {
          Model::RowList row_list;

          for (const auto &event : event_list) {
            if (event.identifier == d->execve_identifier ||
                event.identifier == d->execveat_identifier) {
              processExecEvent(event);
              continue;
            }

            Model::Row row{};

            if (event.identifier == d->connect_identifier) {
              processConnectEvent(row, event);

            } else if (event.identifier == d->bind_identifier) {
              processBindEvent(row, event);

            } else if (event.identifier == d->accept_identifier ||
                       event.identifier == d->accept4_identifier) {
              processAcceptEvent(row, event);
            }

            row_list.push_back(std::move(row));
          }

          std::lock_guard<std::mutex> lock(d->row_list_mutex);

          d->row_list.insert(d->row_list.end(),
                             std::make_move_iterator(row_list.begin()),
                             std::make_move_iterator(row_list.end()));
        });
  }
}

void Tracer::processExecEvent(
    const tob::ebpfpub::IFunctionTracer::Event &event) {
  const auto &filename =
      std::get<std::string>(event.in_field_map.at("filename").data_var);

  d->process_id_map.insert({event.header.process_id, filename});
}

std::string Tracer::getProcessFilename(pid_t process_id) const {
  auto filename_it = d->process_id_map.find(process_id);
  if (filename_it != d->process_id_map.end()) {
    return filename_it->second;
  }

  auto link_path = std::string("/proc/") + std::to_string(process_id) + "/exe";

  std::vector<char> buffer(SSIZE_MAX, 0);
  if (readlink(link_path.c_str(), buffer.data(), buffer.size() - 1) != -1) {
    return buffer.data();
  }

  return std::string();
}

void Tracer::processConnectEvent(
    Model::Row &row, const tob::ebpfpub::IFunctionTracer::Event &event) {

  row = {};
  generateHeaderData(row, event);

  row.executable_path = getProcessFilename(event.header.process_id);

  auto fd = std::get<std::uint64_t>(event.in_field_map.at("fd").data_var);

  const auto &uservaddr =
      std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
          event.in_field_map.at("uservaddr").data_var);

  auto addrlen =
      std::get<std::uint64_t>(event.in_field_map.at("addrlen").data_var);

  std::string address;
  parseSockaddrStructure(address, uservaddr);

  std::stringstream output;
  output << "uservaddr: " << address << "fd:" << fd << " "
         << "addrlen: " << addrlen;

  row.event_data = output.str();
}

void Tracer::processBindEvent(
    Model::Row &row, const tob::ebpfpub::IFunctionTracer::Event &event) {

  row = {};
  generateHeaderData(row, event);

  row.executable_path = getProcessFilename(event.header.process_id);

  auto fd = std::get<std::uint64_t>(event.in_field_map.at("fd").data_var);
  const auto &umyaddr =
      std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
          event.in_field_map.at("umyaddr").data_var);
  auto addrlen =
      std::get<std::uint64_t>(event.in_field_map.at("addrlen").data_var);

  std::string address;
  parseSockaddrStructure(address, umyaddr);

  std::stringstream output;
  output << "umyaddr: " << address << "fd:" << fd << " "
         << "addrlen: " << addrlen;

  row.event_data = output.str();
}

void Tracer::processAcceptEvent(
    Model::Row &row, const tob::ebpfpub::IFunctionTracer::Event &event) {

  row = {};
  generateHeaderData(row, event);

  row.executable_path = getProcessFilename(event.header.process_id);

  auto fd = std::get<std::uint64_t>(event.in_field_map.at("fd").data_var);
  const auto &upeer_sockaddr =
      std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
          event.out_field_map.at("upeer_sockaddr").data_var);
  auto upeer_addrlen =
      std::get<std::uint64_t>(event.out_field_map.at("upeer_addrlen").data_var);

  std::string address;
  parseSockaddrStructure(address, upeer_sockaddr);

  std::stringstream output;
  output << "upeer_sockaddr: " << address << "fd:" << fd << " "
         << "upeer_addrlen: " << upeer_addrlen;

  if (event.identifier == d->accept4_identifier) {
    auto flags =
        std::get<std::uint64_t>(event.in_field_map.at("flags").data_var);

    output << "flags: " << flags;
  }

  row.event_data = output.str();
}
