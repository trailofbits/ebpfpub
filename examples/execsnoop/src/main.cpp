/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <iomanip>
#include <iostream>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <tob/ebpf/perfeventarray.h>

#include <netinet/in.h>
#include <sys/resource.h>

void setRlimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto error = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (error != 0) {
    throw std::runtime_error("Failed to set RLIMIT_MEMLOCK");
  }
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

    std::cout << "  " << event.name << "(";

    add_separator = false;
    for (const auto &field : event.field_list) {
      if (add_separator) {
        std::cout << ", ";
      }

      add_separator = true;
      std::string mode;
      if (field.in) {
        mode = "in";
      } else {
        mode = "out";
      }

      std::cout << field.name << ":" << mode << "=";

      if (std::holds_alternative<std::uint64_t>(field.data_var)) {
        std::cout << std::get<std::uint64_t>(field.data_var);

      } else if (std::holds_alternative<
                     tob::ebpfpub::IFunctionTracer::Event::Field::Argv>(
                     field.data_var)) {

        const auto &argv_data =
            std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Argv>(
                field.data_var);

        std::cout << "{ ";
        for (auto it = argv_data.begin(); it != argv_data.end(); ++it) {

          const auto &argv_entry = *it;
          std::cout << argv_entry;

          if (std::next(it, 1) < argv_data.end()) {
            std::cout << ", ";
          }
        }
        std::cout << " }";

      } else if (std::holds_alternative<std::string>(field.data_var)) {
        std::cout << std::get<std::string>(field.data_var);
      }
    }
  }

  std::cout << ")\n\n";
}

int main(int argc, char *argv[]) {
  setRlimit();

  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(1024, 4096);
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

  auto perf_event_reader_exp = tob::ebpfpub::IPerfEventReader::create(
      *perf_event_array.get(), *buffer_storage.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  auto perf_event_reader = perf_event_reader_exp.takeValue();

  const std::vector<std::string> kSyscallNameList = {"execve", "execveat"};

  for (const auto &syscall_name : kSyscallNameList) {
    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            syscall_name, *buffer_storage.get(), *perf_event_array.get(), 2048);

    if (!function_tracer_exp.succeeded()) {
      throw std::runtime_error("Failed to create the function tracer: " +
                               function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();
    perf_event_reader->insert(std::move(function_tracer));
  }

  // Main event loop
  while (true) {
    perf_event_reader->exec(std::chrono::seconds(1U), eventParser);
  }

  return 0;
}
