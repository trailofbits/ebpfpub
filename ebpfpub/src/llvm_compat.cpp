/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "llvm_compat.h"

namespace tob::ebpfpub {
llvm::StructType *getTypeByName(const llvm::Module &module,
                                llvm::StringRef name) {
#if LLVM_VERSION_MAJOR >= 12
  auto &context = module.getContext();
  return llvm::StructType::getTypeByName(context, name);

#else
  return module.getTypeByName(name);
#endif
}
} // namespace tob::ebpfpub
