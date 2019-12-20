/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "bpfprogramwriter.h"
#include "bufferreader.h"

#include <llvm/IR/DerivedTypes.h>

#include <ebpfpub/isyscalltracepoint.h>

namespace tob::ebpfpub {
class SyscallTracepoint final : public ISyscallTracepoint {
public:
  virtual ~SyscallTracepoint();

  virtual const std::string &syscallName() const override;
  virtual const std::string &serializerName() const override;

  virtual StringErrorOr<std::string> generateIR() const override;
  virtual std::uint32_t eventIdentifier() const override;

  StringErrorOr<EventList> parseEvents(BufferReader &buffer_reader) const;

  SuccessOrStringError start();
  void stop();

protected:
  SyscallTracepoint(const std::string &syscall_name,
                    IBufferStorage &buffer_storage,
                    ebpf::PerfEventArray &perf_event_array,
                    std::size_t event_map_size);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  SuccessOrStringError generateEnterFunction(BPFProgramWriter &bpf_prog_writer);

  SuccessOrStringError
  initializeExitFunction(BPFProgramWriter &bpf_prog_writer);

  SuccessOrStringError finalizeExitFunction(BPFProgramWriter &bpf_prog_writer);

  StringErrorOr<std::vector<std::string>> getTracepointEnableSwitchList();

  SuccessOrStringError enableTracepoints();
  SuccessOrStringError disableTracepoints();

  friend class ISyscallTracepoint;
};
} // namespace tob::ebpfpub
