/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <ebpfpub/ifunctiontracer.h>

namespace tob::ebpfpub {
class ReadlineSerializer final : public IFunctionSerializer {
public:
  static StringErrorOr<Ref> create();
  virtual ~ReadlineSerializer() override;

  virtual const std::string &name() const override;

  virtual SuccessOrStringError
  generate(const ebpf::Structure &enter_structure,
           IBPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(Event &event, IBufferReader &buffer_reader,
              IBufferStorage &buffer_storage) override;

private:
  ReadlineSerializer();
};
} // namespace tob::ebpfpub
