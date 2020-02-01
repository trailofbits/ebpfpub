/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "bpfprogramwriter.h"

#include <llvm/IR/DerivedTypes.h>

#include <ebpfpub/ifunctiontracer.h>
#include <tob/ebpf/iperfevent.h>

namespace tob::ebpfpub {
class FunctionTracer final : public IFunctionTracer {
public:
  using Ref = std::unique_ptr<FunctionTracer>;

  struct EventData final {
    std::string name;
    BPFProgramWriter::ProgramType program_type;

    ebpf::Structure enter_structure;
    ebpf::IPerfEvent::Ref enter_event;

    ebpf::Structure exit_structure;
    ebpf::IPerfEvent::Ref exit_event;
  };

  ~FunctionTracer();

  virtual const std::string &name() const override;
  virtual std::uint32_t eventIdentifier() const override;

  StringErrorOr<IFunctionSerializer::EventList>
  parseEvents(IBufferReader &buffer_reader) const;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  FunctionTracer(EventData event_data, IFunctionSerializer::Ref serializer,
                 std::size_t event_map_size, IBufferStorage &buffer_storage,
                 ebpf::PerfEventArray &perf_event_array);

  SuccessOrStringError generateEnterFunction(BPFProgramWriter &bpf_prog_writer);

  SuccessOrStringError
  initializeExitFunction(BPFProgramWriter &bpf_prog_writer);

  SuccessOrStringError finalizeExitFunction(BPFProgramWriter &bpf_prog_writer);

  friend class IFunctionTracer;
};
} // namespace tob::ebpfpub
