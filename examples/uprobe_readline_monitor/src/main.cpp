#include "readlineserializer.h"

#include <atomic>
#include <cstring>
#include <iostream>
#include <vector>

#include <signal.h>
#include <sys/resource.h>

#include <CLI/CLI.hpp>

#include <ebpfpub/iperfeventreader.h>

namespace {
std::atomic_bool terminate{false};

void signalHandler(int signal) {
  if (signal != SIGINT) {
    return;
  }

  terminate = true;
}

void setRlimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto error = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (error != 0) {
    throw std::runtime_error("Failed to set RLIMIT_MEMLOCK");
  }
}

void printEventHeader(
    const tob::ebpfpub::IFunctionSerializer::Event::Header &header) {
  std::cout << "timestamp: " << header.timestamp << " ";

  std::cout << "process_id: " << header.process_id << " ";
  std::cout << "thread_id: " << header.thread_id << " ";

  std::cout << "user_id: " << header.user_id << " ";
  std::cout << "group_id: " << header.group_id << " ";

  std::cout << "exit_code: " << header.exit_code << " ";
  std::cout << "probe_error: " << header.probe_error << "\n";
}

void printEventOptionalVariant(
    const tob::ebpfpub::IFunctionSerializer::Event::OptionalVariant
        &opt_variant) {

  if (!opt_variant.has_value()) {
    std::cout << "<NULL>";
    return;
  }

  auto variant = opt_variant.value();

  if (std::holds_alternative<std::string>(variant)) {
    const auto &value = std::get<std::string>(variant);
    std::cout << "'" << value << "'";

  } else if (std::holds_alternative<std::vector<std::uint8_t>>(variant)) {

    const auto &value = std::get<std::vector<std::uint8_t>>(variant);

    std::cout << "<buffer of " << value.size() << " bytes>";

  } else if (std::holds_alternative<
                 tob::ebpfpub::IFunctionSerializer::Event::Integer>(variant)) {

    const auto &integer =
        std::get<tob::ebpfpub::IFunctionSerializer::Event::Integer>(variant);

    if (integer.is_signed) {
      std::cout << static_cast<int>(integer.value);
    } else {
      std::cout << static_cast<std::uint64_t>(integer.value);
    }

  } else {
    std::cout << "<ERROR>";
  }
}

void printEvent(const tob::ebpfpub::IFunctionSerializer::Event &event) {
  printEventHeader(event.header);

  std::cout << "syscall: " << event.name << " ";

  for (const auto &field : event.field_map) {
    const auto &field_name = field.first;
    const auto &field_opt_variant = field.second;

    std::cout << field_name << ": ";
    printEventOptionalVariant(field_opt_variant);

    std::cout << " ";
  }

  std::cout << "\n\n";
}
} // namespace

int main(int argc, char *argv[]) {
  setRlimit();
  signal(SIGINT, signalHandler);

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;

  {
    auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(4096U, 100U);

    if (!buffer_storage_exp.succeeded()) {
      const auto &error = buffer_storage_exp.error();
      std::cerr << error.message() << "\n";

      return 1;
    }

    buffer_storage = buffer_storage_exp.takeValue();
  }

  tob::ebpf::PerfEventArray::Ref perf_event_array;

  {
    auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(10U);

    if (!perf_event_array_exp.succeeded()) {
      const auto &error = perf_event_array_exp.error();
      std::cerr << error.message() << "\n";

      return 1;
    }

    perf_event_array = perf_event_array_exp.takeValue();
  }

  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;

  {
    auto perf_event_reader_exp = tob::ebpfpub::IPerfEventReader::create(
        *perf_event_array.get(), *buffer_storage.get());

    if (!perf_event_reader_exp.succeeded()) {
      const auto &error = perf_event_reader_exp.error();
      std::cerr << error.message() << "\n";

      return 1;
    }

    perf_event_reader = perf_event_reader_exp.takeValue();
  }

  const tob::ebpf::Structure readline_argument_list = {
      {"const char *", "prompt", 0U, 8U, false}};

  auto serializer_exp = tob::ebpfpub::ReadlineSerializer::create();
  if (!serializer_exp.succeeded()) {
    const auto &error = serializer_exp.error();
    std::cerr << error.message() << "\n";

    return 1;
  }

  auto serializer = serializer_exp.takeValue();

  auto function_tracer_exp = tob::ebpfpub::IFunctionTracer::createFromUprobe(
      "readline", "/usr/lib/libreadline.so.8.0", readline_argument_list,
      *buffer_storage.get(), *perf_event_array.get(), 256U,
      std::move(serializer));

  if (!function_tracer_exp.succeeded()) {
    const auto &error = function_tracer_exp.error();
    std::cerr << error.message() << "\n";

    return 1;
  }

  auto function_tracer = function_tracer_exp.takeValue();
  perf_event_reader->insert(std::move(function_tracer));

  std::cout << "\nEntering main loop...\n\n";

  // clang-format off
  auto success_exp = perf_event_reader->exec(
    terminate,

    [](const tob::ebpfpub::IFunctionSerializer::EventList &event_list) -> void {
      for (const auto &event : event_list) {
        printEvent(event);
      }
    }
  );
  // clang-format on

  std::cout << "\nTerminating...\n";

  if (success_exp.failed()) {
    const auto &error = success_exp.error();
    std::cerr << error.message() << "\n";
  }

  return 0;
}
