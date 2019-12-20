/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "isyscallserializer.h"

#include <memory>

namespace tob::ebpfpub {
class ConnectSyscallSerializer final : public ISyscallSerializer {
public:
  ConnectSyscallSerializer();
  virtual ~ConnectSyscallSerializer() override;

  virtual const std::string &name() const override;

  virtual SuccessOrStringError
  generate(const ebpf::TracepointEvent &enter_event,
           BPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(ISyscallTracepoint::Event &event, BufferReader &buffer_reader,
              BufferStorage &buffer_storage) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace tob::ebpfpub
