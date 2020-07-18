/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/ifunctiontracer.h>

namespace tob::ebpfpub {
class TracepointSerializers final {
public:
  TracepointSerializers();
  ~TracepointSerializers();

  StringErrorOr<IFunctionTracer::ParameterList>
  getParameterList(const std::string &syscall_name);

  TracepointSerializers(const TracepointSerializers &) = delete;
  TracepointSerializers &operator=(const TracepointSerializers &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace tob::ebpfpub
