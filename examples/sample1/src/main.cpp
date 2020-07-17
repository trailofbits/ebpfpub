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

tob::StringErrorOr<tob::ebpfpub::IFunctionTracer::Ref>
generateKprobeFunctionTracerForOpenat2(
    tob::ebpfpub::IBufferStorage &buffer_storage,
    tob::ebpf::PerfEventArray &perf_event_array) {

  //  https://man7.org/linux/man-pages/man2/openat2.2.html
  //
  //  Note: There is no glibc wrapper for this system call; see NOTES.
  //
  //  The open_how structure
  //      The how argument specifies how pathname should be opened, and acts as
  //      a superset of the flags and mode arguments to openat(2).  This
  //      argument is a pointer to a structure of the following form:
  //
  //          struct open_how {
  //              u64 flags;    /* O_* flags */
  //              u64 mode;     /* Mode for O_{CREAT,TMPFILE} */
  //              u64 resolve;  /* RESOLVE_* flags */
  //              /* ... */
  //          };

  struct open_how {
    std::uint64_t flags;
    std::uint64_t mode;
    std::uint64_t resolve;
  };

  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "dfd",
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
      "how",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      sizeof(open_how)
    },

    {
      "usize",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    },
  };
  // clang-format on

  return tob::ebpfpub::IFunctionTracer::createFromKprobe(
      "do_sys_openat2", parameter_list, buffer_storage, perf_event_array, 2048);
}

tob::StringErrorOr<tob::ebpfpub::IFunctionTracer::Ref>
generateFunctionTracerForOpenatTracepoint(
    tob::ebpfpub::IBufferStorage &buffer_storage,
    tob::ebpf::PerfEventArray &perf_event_array) {

  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "dfd",
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
      "flags",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    },

    {
      "mode",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    }
  };
  // clang-format on

  return tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
      "openat", parameter_list, buffer_storage, perf_event_array, 2048);
}

tob::StringErrorOr<tob::ebpfpub::IFunctionTracer::Ref>
generateFunctionTracerForTracepoint(
    const std::string &syscall_name,
    tob::ebpfpub::IBufferStorage &buffer_storage,
    tob::ebpf::PerfEventArray &perf_event_array) {

  return tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
      syscall_name, buffer_storage, perf_event_array, 2048);
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
                     tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
                     field.data_var)) {

        const auto &buffer =
            std::get<tob::ebpfpub::IFunctionTracer::Event::Field::Buffer>(
                field.data_var);

        std::cout << "{";
        for (const auto &b : buffer) {
          std::cout << " 0x" << std::setw(2) << std::setfill('0') << std::hex
                    << static_cast<int>(b);
        }

        std::cout << " } -> " << std::dec;

        sa_family_t sa_family{0U};
        std::memcpy(&sa_family, buffer.data(), sizeof(sa_family));

        // TODO(alessandro): buffer can be smaller than what is required
        switch (sa_family) {
        case AF_INET: {
          std::cout << "AF_INET: ";

          struct sockaddr_in temp = {};
          std::memcpy(&temp, buffer.data(), sizeof(temp));

          std::uint8_t address_parts[4U] = {};
          std::memcpy(address_parts, &temp.sin_addr.s_addr,
                      sizeof(address_parts));

          std::cout << static_cast<int>(address_parts[0]) << "."
                    << static_cast<int>(address_parts[1]) << "."
                    << static_cast<int>(address_parts[2]) << "."
                    << static_cast<int>(address_parts[3]);

          std::cout << ":" << htons(temp.sin_port);
          break;
        }

        default:
          std::cout << "? (" << sa_family << ")";
          ;
          break;
        }

      } else if (std::holds_alternative<
                     tob::ebpfpub::IFunctionTracer::Event::Field::Argv>(
                     field.data_var)) {

        std::cout << "<ARGV_OBJECT>";

      } else if (std::holds_alternative<std::string>(field.data_var)) {
        std::cout << std::get<std::string>(field.data_var);

      } else {
        std::cout << "Invalid parameter type\n";
        break;
      }
    }
  }

  std::cout << ")\n\n";
}

int main(int argc, char *argv[]) {
  setRlimit();

  // Create a buffer storage; we'll use it to store buffers and strings.
  // In this case, we are allocating 1024 buffers of 1 KiB each.
  auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(1024, 1024);
  if (!buffer_storage_exp.succeeded()) {
    throw std::runtime_error("Failed to create the buffer storage: " +
                             buffer_storage_exp.error().message());
  }

  auto buffer_storage = buffer_storage_exp.takeValue();

  // Create a perf event array, which is used by the BPF code to send events
  // back to us
  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(12);
  if (!perf_event_array_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event array: " +
                             perf_event_array_exp.error().message());
  }

  auto perf_event_array = perf_event_array_exp.takeValue();

  // Create a perf event reader, which will take care of reading back the data
  // that the BPF program generates
  auto perf_event_reader_exp = tob::ebpfpub::IPerfEventReader::create(
      *perf_event_array.get(), *buffer_storage.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  auto perf_event_reader = perf_event_reader_exp.takeValue();

  // Create the function tracer; we need to pass the buffer storage where we
  // want to store our strings and buffers, and also the perf event array used
  // by the BPF probe to wake us up

  const std::vector<std::string> kSyscallNameList = {
      "connect",
      //"bind",
      //"accept",
      //"accept4",
  };

  for (const auto &syscall_name : kSyscallNameList) {
    auto function_tracer_exp = generateFunctionTracerForTracepoint(
        syscall_name, *buffer_storage.get(), *perf_event_array.get());

    if (!function_tracer_exp.succeeded()) {
      throw std::runtime_error("Failed to create the function tracer: " +
                               function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();
    perf_event_reader->insert(std::move(function_tracer));
  }

  // Kprobe test
  if (false) {
    auto function_tracer_exp = generateKprobeFunctionTracerForOpenat2(
        *buffer_storage.get(), *perf_event_array.get());

    if (!function_tracer_exp.succeeded()) {
      throw std::runtime_error("Failed to create the function tracer: " +
                               function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();
    perf_event_reader->insert(std::move(function_tracer));
  }

  // Custom tracepoint test
  if (false) {
    auto function_tracer_exp = generateFunctionTracerForOpenatTracepoint(
        *buffer_storage.get(), *perf_event_array.get());

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
