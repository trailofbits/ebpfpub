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

const std::string kSystemdSharedPath{
    "/usr/lib/systemd/libsystemd-shared-250.so"};

// clang-format off
tob::ebpfpub::IFunctionTracer::ParameterList kParameterList = {
  {
    "p",
    tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
    tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
    {}
  },
};
// clang-format on

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
              << "exit_code: " << event.header.exit_code << " "
              << "probe_error: " << event.header.probe_error << " "
              << "duration: " << event.header.duration << "\n";

    std::cout << "  " << event.name << "(";

    const auto &prompt =
        std::get<std::string>(event.in_field_map.at("p").data_var);

    std::cout << "p: " << prompt << ")\n\n";
  }
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

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  auto perf_event_reader = perf_event_reader_exp.takeValue();

  auto function_tracer_exp = tob::ebpfpub::IFunctionTracer::createFromUprobe(
      "dns_name_address", kSystemdSharedPath, kParameterList,
      *buffer_storage.get(), *perf_event_array.get(), 1024);

  if (!function_tracer_exp.succeeded()) {
    throw std::runtime_error("Failed to initialize the function tracer");
  }

  auto function_tracer = function_tracer_exp.takeValue();
  perf_event_reader->insert(std::move(function_tracer));

  while (true) {
    perf_event_reader->exec(std::chrono::seconds(1U), eventParser);
  }

  return 0;
}
