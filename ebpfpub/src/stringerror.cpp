/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <ebpfpub/error.h>

namespace ebpfpub {
StringError StringError::create(const std::string &message) {
  return StringError(message);
}

StringError::StringError() : message_("Uninitialized error mesage") {}

const std::string &StringError::message() const { return message_; }

StringError::StringError(const std::string &message) : message_(message) {}
} // namespace ebpfpub
