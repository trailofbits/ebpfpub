/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <llvm/IR/Module.h>

#include <tob/error/stringerror.h>

namespace tob::ebpfpub {
class ForkNamespaceHelper final {
public:
  using Ref = std::unique_ptr<ForkNamespaceHelper>;
  static StringErrorOr<Ref> create(int event_map_fd);

  virtual ~ForkNamespaceHelper();

  ForkNamespaceHelper(const ForkNamespaceHelper &) = delete;
  ForkNamespaceHelper &operator=(const ForkNamespaceHelper &) = delete;

protected:
  ForkNamespaceHelper(int event_map_fd);

public:
  static SuccessOrStringError
  importFunctionTracerEventHeader(llvm::Module &module);

  static SuccessOrStringError createFunctionArgumentType(llvm::Module &module);

  static SuccessOrStringError generateFunction(llvm::Module &module,
                                               int event_map_fd);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace tob::ebpfpub
