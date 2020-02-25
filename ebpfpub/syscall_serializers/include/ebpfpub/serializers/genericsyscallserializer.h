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
class GenericSyscallSerializer final : public IFunctionSerializer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  GenericSyscallSerializer(IBufferStorage &buffer_storage);
  virtual ~GenericSyscallSerializer() override;

  static const std::string name;
  virtual const std::string &getName() const override;
  virtual const StageList &stages() const override;

  virtual SuccessOrStringError
  generate(Stage stage, const ebpf::Structure &enter_structure,
           IBPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(IFunctionSerializer::Event &event, IBufferReader &buffer_reader,
              IBufferStorage &buffer_storage) override;
};
} // namespace tob::ebpfpub
