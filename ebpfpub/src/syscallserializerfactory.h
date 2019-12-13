/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "isyscallserializer.h"

#include <ebpfpub/error.h>

namespace ebpfpub {
SuccessOrStringError initializeSerializerFactory();

StringErrorOr<ISyscallSerializer::Ref> createSerializer(std::string name);
} // namespace ebpfpub
