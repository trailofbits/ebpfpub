/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "isyscallserializer.h"

#include <memory>

namespace ebpfpub {
class GenericSyscallSerializer final : public ISyscallSerializer {
public:
  GenericSyscallSerializer();
  virtual ~GenericSyscallSerializer() override;

  virtual const std::string &name() const override;

  virtual SuccessOrStringError
  generate(const ITracepointEvent &enter_event,
           BPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(ISyscallTracepoint::Event &event, BufferReader &buffer_reader,
              BufferStorage &buffer_storage) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace ebpfpub
