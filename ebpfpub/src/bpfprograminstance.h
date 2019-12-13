/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "uniquefd.h"

#include <unordered_map>
#include <vector>

#include <linux/bpf.h>
#include <llvm/IR/Module.h>

#include <ebpfpub/itracepointevent.h>

namespace ebpfpub {
using BPFProgram = std::vector<struct bpf_insn>;
using BPFProgramSet = std::unordered_map<std::string, BPFProgram>;

class BPFProgramInstance final {
public:
  using Ref = std::unique_ptr<BPFProgramInstance>;
  static StringErrorOr<Ref>
  loadProgram(const BPFProgram &program,
              const ITracepointEvent &tracepoint_event);

  ~BPFProgramInstance();

  BPFProgramInstance(BPFProgramInstance &&other);
  BPFProgramInstance &operator=(BPFProgramInstance &&other);

  BPFProgramInstance(const BPFProgramInstance &) = delete;
  BPFProgramInstance &operator=(const BPFProgramInstance &) = delete;

protected:
  BPFProgramInstance(const BPFProgram &program,
                     const ITracepointEvent &tracepoint_event);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  SuccessOrStringError activateSystemTracepoint(bool enable);
};

// clang-format off
static_assert(
  std::is_move_constructible<BPFProgramInstance>::value &&
  std::is_move_assignable<BPFProgramInstance>::value,

  "BPFProgramInstance must be movable"
);
// clang-format on

StringErrorOr<BPFProgramSet> compileModule(llvm::Module &original_module);
} // namespace ebpfpub
