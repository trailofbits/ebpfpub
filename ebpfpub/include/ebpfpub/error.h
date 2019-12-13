/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/errorcode.h>
#include <ebpfpub/erroror.h>
#include <ebpfpub/stringerror.h>
#include <ebpfpub/successor.h>

namespace ebpfpub {
template <typename ValueType>
using StringErrorOr = ErrorOr<ValueType, StringError>;

using SuccessOrStringError = SuccessOr<StringError>;
} // namespace ebpfpub
