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

#include <btfparse/ibtf.h>

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
              << "probe_error: " << event.header.probe_error << " "
              << "duration: " << event.header.duration << "\n";

    if (event.header.opt_cgroup_name_slices.has_value()) {
      const auto &cgroup_name_slices =
          event.header.opt_cgroup_name_slices.value();

      std::cout << "cgroup_name: ";

      for (auto it = cgroup_name_slices.begin(); it != cgroup_name_slices.end();
           ++it) {

        const auto &cgroup_name = *it;
        std::cout << "'" << cgroup_name << "'";

        if (std::next(it, 1) != cgroup_name_slices.end()) {
          std::cout << ", ";
        }
      }

      std::cout << "\n";
    }

    std::cout << "  " << event.name << "(";

    const auto &filename =
        std::get<std::string>(event.in_field_map.at("filename").data_var);

    std::cout << "filename: " << filename << ", ";

    const auto &argument_list =
        std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Argv>(
            event.in_field_map.at("argv").data_var);

    std::cout << "argv: { ";

    for (auto argument_it = argument_list.begin();
         argument_it != argument_list.end(); ++argument_it) {

      const auto &argument = *argument_it;
      std::cout << argument;

      if (std::next(argument_it, 1) < argument_list.end()) {
        std::cout << ", ";
      }
    }

    std::cout << " })\n\n";
  }
}

int main(int argc, char *argv[]) {
  bool enable_btf{false};
  if (argc >= 2 && std::strcmp(argv[1], "--enable-btf") == 0) {
    enable_btf = true;
    std::cout << "cgroup names enabled\n";

  } else {
    std::cout << "You can use --enable-btf to add support for cgroup names\n";
  }

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

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  auto perf_event_reader = perf_event_reader_exp.takeValue();

  btfparse::IBTF::Ptr btf{nullptr};

  if (enable_btf) {
    auto btf_res =
        btfparse::IBTF::createFromPathList({"/sys/kernel/btf/vmlinux"});

    if (btf_res.failed()) {
      std::cerr << "Failed to open the BTF file: " << btf_res.takeError()
                << "\n";
      return 1;
    }

    btf = btf_res.takeValue();
    if (btf->count() == 0) {
      std::cout << "No types were found!\n";
      return 1;
    }
  }

  const std::vector<std::string> kSyscallNameList = {"execve", "execveat"};

  for (const auto &syscall_name : kSyscallNameList) {
    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            syscall_name, *buffer_storage.get(), *perf_event_array.get(), 2048,
            std::nullopt, btf);

    if (!function_tracer_exp.succeeded()) {
      throw std::runtime_error("Failed to create the function tracer: " +
                               function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();
    perf_event_reader->insert(std::move(function_tracer));
  }

  while (true) {
    perf_event_reader->exec(std::chrono::seconds(1U), eventParser);
  }

  return 0;
}
