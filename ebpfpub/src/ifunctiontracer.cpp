/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "functiontracer.h"
#include "kallsymsparser.h"
#include "tracepointserializers.h"

#include <tob/ebpf/iperfevent.h>

namespace tob::ebpfpub {

namespace {

const std::string kKallsymsPath{"/proc/kallsyms"};
}

StringErrorOr<IFunctionTracer::Ref>
IFunctionTracer::createFromSyscallTracepoint(
    const std::string &name, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size,
    OptionalPidList excluded_processes) {

  TracepointSerializers serializers;
  auto param_list_exp = serializers.getParameterList(name);
  if (!param_list_exp.succeeded()) {
    return param_list_exp.error();
  }

  auto parameter_list = param_list_exp.takeValue();
  return createFromSyscallTracepoint(name, parameter_list, buffer_storage,
                                     perf_event_array, event_map_size,
                                     excluded_processes);
}

StringErrorOr<IFunctionTracer::Ref>
IFunctionTracer::createFromSyscallTracepoint(
    const std::string &name, const ParameterList &parameter_list,
    IBufferStorage &buffer_storage, ebpf::PerfEventArray &perf_event_array,
    std::size_t event_map_size, OptionalPidList excluded_processes) {

  try {
    auto event_exp =
        ebpf::IPerfEvent::createTracepoint("syscalls", "sys_enter_" + name);

    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto enter_event = event_exp.takeValue();

    event_exp =
        ebpf::IPerfEvent::createTracepoint("syscalls", "sys_exit_" + name);

    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto exit_event = event_exp.takeValue();

    return Ref(new FunctionTracer(
        name, parameter_list, event_map_size, buffer_storage, perf_event_array,
        std::move(enter_event), std::move(exit_event), excluded_processes));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IFunctionTracer::Ref> IFunctionTracer::createFromKprobe(
    const std::string &name, bool is_syscall,
    const ParameterList &parameter_list, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size,
    OptionalPidList excluded_processes) {

  try {
    auto resolved_name{name};

    if (is_syscall) {
      auto kallsyms_parser_exp = KallsymsParser::create(kKallsymsPath);
      if (!kallsyms_parser_exp.succeeded()) {
        throw kallsyms_parser_exp.error();
      }

      auto kallsyms_parser = kallsyms_parser_exp.takeValue();

      if (kallsyms_parser->contains("sys_bpf")) {
        resolved_name = "sys_" + name;

      } else if (kallsyms_parser->contains("__x64_sys_bpf")) {
        resolved_name = "__x64_sys_" + name;

      } else if (kallsyms_parser->contains("__arm64_sys_bpf")) {
        resolved_name = "__arm64_sys_" + name;
      }
    }

    // Create the enter event
    auto event_exp =
        ebpf::IPerfEvent::createKprobe(resolved_name, is_syscall, false);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto enter_event = event_exp.takeValue();

    // Create the exit event
    event_exp = ebpf::IPerfEvent::createKprobe(resolved_name, is_syscall, true);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto exit_event = event_exp.takeValue();

    // Create the function tracer using the events we obtained
    return Ref(new FunctionTracer(resolved_name, parameter_list, event_map_size,
                                  buffer_storage, perf_event_array,
                                  std::move(enter_event), std::move(exit_event),
                                  excluded_processes));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IFunctionTracer::Ref> IFunctionTracer::createFromUprobe(
    const std::string &name, const std::string &path,
    const ParameterList &parameter_list, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size,
    OptionalPidList excluded_processes) {

  try {
    // Create the enter event
    auto event_exp = ebpf::IPerfEvent::createUprobe(name, path, false);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto enter_event = event_exp.takeValue();

    // Create the exit event
    event_exp = ebpf::IPerfEvent::createUprobe(name, path, true);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto exit_event = event_exp.takeValue();

    // Create the function tracer using the events we obtained
    return Ref(new FunctionTracer(
        name, parameter_list, event_map_size, buffer_storage, perf_event_array,
        std::move(enter_event), std::move(exit_event), excluded_processes));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
