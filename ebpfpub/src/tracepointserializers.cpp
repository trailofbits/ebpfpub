/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "tracepointserializers.h"

#include <iostream>
#include <unordered_map>

#include <tob/ebpf/tracepointdescriptor.h>

namespace tob::ebpfpub {
namespace {
using ParameterListMap =
    std::unordered_map<std::string, IFunctionTracer::ParameterList>;

void initializeParameterListForConnect(ParameterListMap &param_list_map) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "fd",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    },

    {
      "uservaddr",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      "addrlen"
    },

    {
      "addrlen",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    }
  };
  // clang-format on

  param_list_map.insert({"connect", std::move(parameter_list)});
}

void initializeParameterListForAccept(ParameterListMap &param_list_map) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "fd",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    },

    {
      "upeer_sockaddr",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
      "upeer_addrlen"
    },

    {
      "upeer_addrlen",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
      4U
    }
  };
  // clang-format on

  param_list_map.insert({"accept", std::move(parameter_list)});
}

void initializeParameterListForAccept4(ParameterListMap &param_list_map) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "fd",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    },

    {
      "upeer_sockaddr",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
      "upeer_addrlen"
    },

    {
      "upeer_addrlen",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
      4U
    },

    {
      "flags",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    }
  };
  // clang-format on

  param_list_map.insert({"accept4", std::move(parameter_list)});
}

void initializeParameterListForBind(ParameterListMap &param_list_map) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "fd",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    },

    {
      "umyaddr",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      "addrlen"
    },

    {
      "addrlen",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    }
  };
  // clang-format on

  param_list_map.insert({"bind", std::move(parameter_list)});
}

void initializeParameterListForForkAndVfork(ParameterListMap &param_list_map) {
  param_list_map.insert({"fork", {}});
  param_list_map.insert({"vfork", {}});
}

void initializeParameterListForExecve(ParameterListMap &param_list_map) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
    {
      "filename",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      {}
    },

    {
      "argv",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Argv,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      20U
    },

    {
      "envp",
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      8U
    }
  };
  // clang-format on

  param_list_map.insert({"execve", std::move(parameter_list)});
}

void initializeParameterListForExecveAt(ParameterListMap &param_list_map) {
  // clang-format off
  tob::ebpfpub::IFunctionTracer::ParameterList parameter_list = {
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
      tob::ebpfpub::IFunctionTracer::Parameter::Type::Argv,
      tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
      20U
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

  param_list_map.insert({"execveat", std::move(parameter_list)});
}

void initializeParameterListMap(ParameterListMap &param_list_map) {
  initializeParameterListForConnect(param_list_map);
  initializeParameterListForAccept(param_list_map);
  initializeParameterListForAccept4(param_list_map);
  initializeParameterListForBind(param_list_map);
  initializeParameterListForForkAndVfork(param_list_map);
  initializeParameterListForExecve(param_list_map);
  initializeParameterListForExecveAt(param_list_map);
}
} // namespace

struct TracepointSerializers::PrivateData final {
  ParameterListMap param_list_map;
};

TracepointSerializers::TracepointSerializers() : d(new PrivateData) {
  initializeParameterListMap(d->param_list_map);
}

TracepointSerializers::~TracepointSerializers() {}

StringErrorOr<IFunctionTracer::ParameterList>
TracepointSerializers::getParameterList(const std::string &syscall_name) {
  auto it = d->param_list_map.find(syscall_name);
  if (it != d->param_list_map.end()) {
    return it->second;
  }

  auto tracepoint_name = "sys_enter_" + syscall_name;

  auto tracepoint_descriptor_exp =
      ebpf::TracepointDescriptor::create("syscalls", tracepoint_name);

  if (!tracepoint_descriptor_exp.succeeded()) {
    return tracepoint_descriptor_exp.error();
  }

  auto tracepoint_descriptor = tracepoint_descriptor_exp.takeValue();

  auto structure = tracepoint_descriptor->structure();
  IFunctionTracer::ParameterList parameter_list;

  for (auto field_it = std::next(structure.begin(), 5);
       field_it < structure.end(); ++field_it) {

    const auto &field_name = field_it->name;
    const auto &field_size = field_it->size;

    // clang-format off
    parameter_list.push_back(
      {
        field_name,
        tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
        tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
        field_size
      }
    );
    // clang-format on
  }

  return parameter_list;
}
} // namespace tob::ebpfpub
