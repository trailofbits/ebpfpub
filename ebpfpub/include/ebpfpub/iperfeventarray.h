/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <ebpfpub/error.h>

namespace ebpfpub {
class IPerfEventArray {
public:
  using Ref = std::shared_ptr<IPerfEventArray>;
  static StringErrorOr<Ref> create(std::size_t per_bpf_output_page_exponent);

  IPerfEventArray() = default;
  virtual ~IPerfEventArray() = default;

  virtual std::size_t memoryUsage() const = 0;

  IPerfEventArray(const IPerfEventArray &) = delete;
  IPerfEventArray &operator=(const IPerfEventArray &) = delete;
};
} // namespace ebpfpub
