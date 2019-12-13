/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/uniqueref.h>

namespace ebpfpub {
struct FdDeleter final {
  using Reference = int;
  static const Reference kNullReference{-1};

  void operator()(Reference fd) const;
};

using UniqueFd = UniqueRef<FdDeleter>;
} // namespace ebpfpub
