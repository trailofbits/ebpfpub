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
