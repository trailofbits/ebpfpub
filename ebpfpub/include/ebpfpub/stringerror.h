/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <string>

#include <ebpfpub/erroror.h>

namespace ebpfpub {
class StringError final {
public:
  static StringError create(const std::string &message);
  StringError();

  const std::string &message() const;

protected:
  StringError(const std::string &message);

private:
  std::string message_;
};
} // namespace ebpfpub
