/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <ebpfpub/isyscallserializer.h>

namespace tob::ebpfpub {
class ReadlineSerializer final : public ISyscallSerializer {
public:
  ReadlineSerializer();
  virtual ~ReadlineSerializer() override;

  virtual const std::string &name() const override;

  virtual SuccessOrStringError
  generate(const ebpf::Structure &enter_structure,
           BPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(IFunctionTracer::Event &event, BufferReader &buffer_reader,
              BufferStorage &buffer_storage) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace tob::ebpfpub
