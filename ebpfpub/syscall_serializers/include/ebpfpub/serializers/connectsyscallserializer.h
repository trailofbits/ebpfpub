/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <ebpfpub/ifunctionserializer.h>

namespace tob::ebpfpub {
class ConnectSyscallSerializer final : public IFunctionSerializer {
public:
  ConnectSyscallSerializer();
  virtual ~ConnectSyscallSerializer() override;

  virtual const std::string &name() const override;

  virtual SuccessOrStringError
  generate(const ebpf::Structure &enter_structure,
           IBPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(IFunctionSerializer::Event &event, IBufferReader &buffer_reader,
              IBufferStorage &buffer_storage) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace tob::ebpfpub
