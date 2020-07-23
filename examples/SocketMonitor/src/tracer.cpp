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
#include <ebpfpub/ifunctiontracer.h>
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

// Custom parameter lists that only dumps the filename string and uses
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

void parseSockaddrStructure(
    std::string &address,
    const tob::ebpfpub::IFunctionTracer::Event::Field::Buffer &buffer) {

  sa_family_t sa_family{0U};
  std::memcpy(&sa_family, buffer.data(), sizeof(sa_family));

  std::stringstream output;

  switch (sa_family) {
  case AF_INET: {
    output << "AF_INET: ";

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
    output << "AF_UNIX: ";

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

void generateEventData(
    std::string &event_data,
    const tob::ebpfpub::IFunctionTracer::Event::FieldList &field_list) {

  std::stringstream output;

  for (const auto &field : field_list) {
    if (std::holds_alternative<std::uint64_t>(field.data_var)) {
      auto value = std::get<std::uint64_t>(field.data_var);
      output << field.name << "=" << value << " ";

    } else if (std::holds_alternative<
                   tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
                   field.data_var)) {
      const auto &buffer =
          std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
              field.data_var);

      std::string address;
      parseSockaddrStructure(address, buffer);

      output << field.name << "=" << address << " ";
    }
  }

  event_data = output.str();
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
            const tob::ebpfpub::IPerfEventReader::ErrorCounters
                &error_counters) {
          Model::RowList row_list;

          for (const auto &event : event_list) {
            if (event.identifier == d->execve_identifier ||
                event.identifier == d->execveat_identifier) {
              auto filename_field_it =
                  std::find_if(event.field_list.begin(), event.field_list.end(),
                               [](const auto &field) -> bool {
                                 return field.name == "filename";
                               });

              Q_ASSERT(filename_field_it != event.field_list.end());

              const auto &filename_field = *filename_field_it;

              Q_ASSERT(
                  std::holds_alternative<std::string>(filename_field.data_var));

              const auto &filename =
                  std::get<std::string>(filename_field.data_var);

              d->process_id_map.insert({event.header.process_id, filename});
              continue;
            }

            Model::Row row{};

            generateEventData(row.event_data, event.field_list);

            row.timestamp = event.header.timestamp;
            row.thread_id = event.header.thread_id;
            row.process_id = event.header.process_id;
            row.user_id = event.header.user_id;
            row.group_id = event.header.group_id;
            row.cgroup_id = event.header.cgroup_id;
            row.exit_code = event.header.exit_code;
            row.syscall_name = event.name;

            auto executable_path_it = d->process_id_map.find(row.process_id);
            if (executable_path_it != d->process_id_map.end()) {
              row.executable_path = executable_path_it->second;

            } else {
              auto link_path = std::string("/proc/") +
                               std::to_string(row.process_id) + "/exe";

              std::vector<char> buffer(SSIZE_MAX, 0);
              if (readlink(link_path.c_str(), buffer.data(), buffer.size()) !=
                  -1) {

                row.executable_path = buffer.data();
              }
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
