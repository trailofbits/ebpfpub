#include "configuration.h"
#include "utils.h"

#include <atomic>
#include <cstring>
#include <iostream>
#include <vector>

#include <signal.h>
#include <sys/resource.h>

#include <CLI/CLI.hpp>

#include <ebpfpub/iperfeventreader.h>

std::atomic_bool terminate{false};

void signalHandler(int signal) {
  if (signal != SIGINT) {
    return;
  }

  terminate = true;
}

void printEventHeader(
    const tob::ebpfpub::ISyscallTracepoint::Event::Header &header) {
  std::cout << "timestamp: " << header.timestamp << " ";

  std::cout << "process_id: " << header.process_id << " ";
  std::cout << "thread_id: " << header.thread_id << " ";

  std::cout << "user_id: " << header.user_id << " ";
  std::cout << "group_id: " << header.group_id << " ";

  std::cout << "exit_code: " << header.exit_code << " ";
  std::cout << "probe_error: " << header.probe_error << "\n";
}

void printEventOptionalVariant(
    const tob::ebpfpub::ISyscallTracepoint::Event::OptionalVariant
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

    std::cout << "<buffer of " << value.size() << " bytes";

  } else if (std::holds_alternative<
                 tob::ebpfpub::ISyscallTracepoint::Event::Integer>(variant)) {

    const auto &integer =
        std::get<tob::ebpfpub::ISyscallTracepoint::Event::Integer>(variant);

    if (integer.is_signed) {
      std::cout << static_cast<int>(integer.value);
    } else {
      std::cout << static_cast<std::uint64_t>(integer.value);
    }

  } else {
    std::cout << "<ERROR>";
  }
}

void printEvent(const tob::ebpfpub::ISyscallTracepoint::Event &event) {
  printEventHeader(event.header);

  std::cout << "syscall: " << event.syscall_name << " ";

  for (const auto &field : event.field_map) {
    const auto &field_name = field.first;
    const auto &field_opt_variant = field.second;

    std::cout << field_name << ": ";
    printEventOptionalVariant(field_opt_variant);

    std::cout << " ";
  }

  std::cout << "\n\n";
}

int main(int argc, char *argv[]) {
  tob::ebpfpub::setRlimit();

  signal(SIGINT, signalHandler);

  tob::ebpfpub::UserSettings user_settings;

  {
    auto user_settings_exp = tob::ebpfpub::parseUserSettings(argc, argv);
    if (!user_settings_exp.succeeded()) {
      std::cerr << user_settings_exp.error().message() << "\n";
      return 1;
    }

    user_settings = user_settings_exp.takeValue();
  }

  tob::ebpfpub::IBufferStorage::Ref buffer_storage;

  {
    auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(
        user_settings.buffer_size, user_settings.buffer_count);

    if (!buffer_storage_exp.succeeded()) {
      const auto &error = buffer_storage_exp.error();
      std::cerr << error.message() << "\n";

      return 1;
    }

    buffer_storage = buffer_storage_exp.takeValue();
  }

  std::cout << "Memory usage\n\n";
  std::cout << " > Buffer storage: " << buffer_storage->memoryUsage()
            << " bytes\n";

  tob::ebpf::PerfEventArray::Ref perf_event_array;

  {
    auto perf_event_array_exp =
        tob::ebpf::PerfEventArray::create(user_settings.perf_event_array_size);

    if (!perf_event_array_exp.succeeded()) {
      const auto &error = perf_event_array_exp.error();
      std::cerr << error.message() << "\n";

      return 1;
    }

    perf_event_array = perf_event_array_exp.takeValue();
  }

  std::cout << " > Perf output: " << perf_event_array->memoryUsage()
            << " bytes\n\n";

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

  std::cout << "Generating the BPF programs...\n\n";

  for (const auto &syscall_name : user_settings.tracepoint_list) {
    tob::ebpfpub::ISyscallTracepoint::Ref syscall_tracepoint = {};
    auto syscall_tracepoint_exp = tob::ebpfpub::ISyscallTracepoint::create(
        syscall_name, *buffer_storage.get(), *perf_event_array.get(),
        user_settings.event_map_size);

    if (!syscall_tracepoint_exp.succeeded()) {
      const auto &error = syscall_tracepoint_exp.error();
      std::cerr << error.message() << "\n";

      return 1;
    }

    syscall_tracepoint = syscall_tracepoint_exp.takeValue();

    std::cout << " > " << syscall_name
              << " (serializer: " << syscall_tracepoint->serializerName()
              << ")\n";

    if (user_settings.verbose_flag) {
      auto module_ir_exp = syscall_tracepoint->generateIR();
      if (!module_ir_exp.succeeded()) {
        const auto &error = module_ir_exp.error();
        std::cerr << error.message() << "\n";

        return 1;
      }

      auto module_ir = module_ir_exp.takeValue();
      std::cout << "IR for '" << syscall_name << "' syscall module:\n====\n"
                << module_ir << "\n\n\n";
    }

    perf_event_reader->insert(std::move(syscall_tracepoint));
  }

  std::cout << "\nEntering main loop...\n\n";

  // clang-format off
  auto success_exp = perf_event_reader->exec(
    terminate,

    [](const tob::ebpfpub::ISyscallTracepoint::EventList &event_list) -> void {
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
