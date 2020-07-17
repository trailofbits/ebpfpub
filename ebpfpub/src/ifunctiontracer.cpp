/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "functiontracer.h"
#include "tracepointserializers.h"

#include <tob/ebpf/iperfevent.h>

namespace tob::ebpfpub {
StringErrorOr<IFunctionTracer::Ref>
IFunctionTracer::createFromSyscallTracepoint(
    const std::string &name, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size) {

  TracepointSerializers serializers;
  auto param_list_exp = serializers.getParameterList(name);
  if (!param_list_exp.succeeded()) {
    return param_list_exp.error();
  }

  auto parameter_list = param_list_exp.takeValue();
  return createFromSyscallTracepoint(name, parameter_list, buffer_storage,
                                     perf_event_array, event_map_size);
}

StringErrorOr<IFunctionTracer::Ref>
IFunctionTracer::createFromSyscallTracepoint(
    const std::string &name, const ParameterList &parameter_list,
    IBufferStorage &buffer_storage, ebpf::PerfEventArray &perf_event_array,
    std::size_t event_map_size) {

  try {
    auto event_exp = ebpf::IPerfEvent::createTracepoint(name, false);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto enter_event = event_exp.takeValue();

    event_exp = ebpf::IPerfEvent::createTracepoint(name, true);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto exit_event = event_exp.takeValue();

    return Ref(new FunctionTracer(
        name, parameter_list, event_map_size, buffer_storage, perf_event_array,
        std::move(enter_event), std::move(exit_event)));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IFunctionTracer::Ref> IFunctionTracer::createFromKprobe(
    const std::string &name, const ParameterList &parameter_list,
    IBufferStorage &buffer_storage, ebpf::PerfEventArray &perf_event_array,
    std::size_t event_map_size) {

  try {
    // Create the enter event
    auto event_exp = ebpf::IPerfEvent::createKprobe(name, false);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto enter_event = event_exp.takeValue();

    // Create the exit event
    event_exp = ebpf::IPerfEvent::createKprobe(name, true);
    if (!event_exp.succeeded()) {
      return event_exp.error();
    }

    auto exit_event = event_exp.takeValue();

    // Create the function tracer using the events we obtained
    return Ref(new FunctionTracer(
        name, parameter_list, event_map_size, buffer_storage, perf_event_array,
        std::move(enter_event), std::move(exit_event)));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

StringErrorOr<IFunctionTracer::Ref> IFunctionTracer::createFromUprobe(
    const std::string &name, const std::string &path,
    const ParameterList &parameter_list, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, std::size_t event_map_size) {

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
        std::move(enter_event), std::move(exit_event)));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
