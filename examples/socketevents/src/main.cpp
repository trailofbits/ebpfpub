/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <iomanip>
#include <iostream>
#include <sstream>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <tob/ebpf/perfeventarray.h>

#include <netinet/in.h>
#include <sys/resource.h>

const std::vector<std::string> kSyscallNameList = {"connect", "bind", "accept",
                                                   "accept4"};

std::uint64_t connect_event_id{0U};
std::uint64_t bind_event_id{0U};
std::uint64_t accept_event_id{0U};
std::uint64_t accept4_event_id{0U};

void setRlimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto error = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (error != 0) {
    throw std::runtime_error("Failed to set RLIMIT_MEMLOCK");
  }
}

std::string parseSockaddrStructure(
    const tob::ebpfpub::IFunctionTracer::Event::Field::Buffer &buffer) {

  sa_family_t sa_family{0U};
  std::memcpy(&sa_family, buffer.data(), sizeof(sa_family));

  if (sa_family == AF_UNSPEC) {
    // A more correct approach is to trace socket() and look
    // at the fd
    sa_family = AF_INET;
  }

  std::stringstream output;

  if (sa_family == AF_INET) {
    struct sockaddr_in address_structure = {};
    std::memcpy(&address_structure, buffer.data(), sizeof(address_structure));

    std::uint8_t address_parts[4U] = {};
    std::memcpy(address_parts, &address_structure.sin_addr.s_addr,
                sizeof(address_parts));

    output << static_cast<int>(address_parts[0]) << "."
           << static_cast<int>(address_parts[1]) << "."
           << static_cast<int>(address_parts[2]) << "."
           << static_cast<int>(address_parts[3]);

    output << ":" << htons(address_structure.sin_port);

  } else {
    output << "<unsupported_sa_family:" << sa_family << ">";
  }

  return output.str();
}

void processConnectEvent(const tob::ebpfpub::IFunctionTracer::Event &event) {

  const auto &uservaddr =
      std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
          event.in_field_map.at("uservaddr").data_var);

  auto address = parseSockaddrStructure(uservaddr);

  std::cout << "  connect(" << address << ")\n\n";
}

void processAcceptEvent(const tob::ebpfpub::IFunctionTracer::Event &event) {

  const auto &upeer_sockaddr =
      std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
          event.out_field_map.at("upeer_sockaddr").data_var);

  auto address = parseSockaddrStructure(upeer_sockaddr);

  std::cout << "  accept(" << address << ")\n\n";
}

void processBindEvent(const tob::ebpfpub::IFunctionTracer::Event &event) {

  const auto &umyaddr =
      std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
          event.in_field_map.at("umyaddr").data_var);

  auto address = parseSockaddrStructure(umyaddr);

  std::cout << "  bind(" << address << ")\n\n";
}

void eventParser(
    const tob::ebpfpub::IFunctionTracer::EventList &event_list,
    const tob::ebpfpub::IPerfEventReader::ErrorCounters &error_counters) {

  bool add_separator = false;
  if (error_counters.invalid_probe_output != 0U) {
    std::cout << "invalid_probe_output: " << error_counters.invalid_probe_output
              << "\n";

    add_separator = true;
  }

  if (error_counters.invalid_event != 0U) {
    std::cout << "invalid_event: " << error_counters.invalid_event << "\n";

    add_separator = true;
  }

  if (error_counters.invalid_event_data != 0U) {
    std::cout << "invalid_event_data: " << error_counters.invalid_event_data
              << "\n";

    add_separator = true;
  }

  if (error_counters.lost_events != 0U) {
    std::cout << "lost_events: " << error_counters.lost_events << "\n";
    add_separator = true;
  }

  if (add_separator) {
    std::cout << "\n";
  }

  for (const auto &event : event_list) {
    std::cout << "timestamp: " << std::dec << event.header.timestamp << " "
              << "thread_id: " << event.header.thread_id << " "
              << "process_id: " << event.header.process_id << " "
              << "uid: " << event.header.user_id << " "
              << "gid: " << event.header.group_id << " "
              << "cgroup_id: " << event.header.cgroup_id << " "
              << "exit_code: " << event.header.exit_code << " "
              << "probe_error: " << event.header.probe_error << "\n";

    if (event.identifier == connect_event_id) {
      processConnectEvent(event);

    } else if (event.identifier == accept_event_id ||
               event.identifier == accept4_event_id) {
      processAcceptEvent(event);

    } else if (event.identifier == bind_event_id) {
      processBindEvent(event);
    } else {
      std::cout << "WTF: " << event.name << std::endl;
    }
  }
}

int main(int argc, char *argv[]) {
  setRlimit();

  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(1024, 1024);
  if (!buffer_storage_exp.succeeded()) {
    throw std::runtime_error("Failed to create the buffer storage: " +
                             buffer_storage_exp.error().message());
  }

  auto buffer_storage = buffer_storage_exp.takeValue();

  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(12);
  if (!perf_event_array_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event array: " +
                             perf_event_array_exp.error().message());
  }

  auto perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  auto perf_event_reader = perf_event_reader_exp.takeValue();

  for (const auto &syscall_name : kSyscallNameList) {
    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            syscall_name, *buffer_storage.get(), *perf_event_array.get(), 2048);

    if (!function_tracer_exp.succeeded()) {
      throw std::runtime_error("Failed to create the function tracer: " +
                               function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();

    if (syscall_name == "connect") {
      connect_event_id = function_tracer->eventIdentifier();

    } else if (syscall_name == "bind") {
      bind_event_id = function_tracer->eventIdentifier();

    } else if (syscall_name == "accept") {
      accept_event_id = function_tracer->eventIdentifier();

    } else if (syscall_name == "accept4") {
      accept4_event_id = function_tracer->eventIdentifier();
    }

    perf_event_reader->insert(std::move(function_tracer));
  }

  while (true) {
    perf_event_reader->exec(std::chrono::seconds(1U), eventParser);
  }

  return 0;
}
