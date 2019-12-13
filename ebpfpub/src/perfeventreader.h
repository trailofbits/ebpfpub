/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/iperfeventreader.h>

namespace ebpfpub {
class PerfEventReader final : public IPerfEventReader {
public:
  virtual ~PerfEventReader() override;

  virtual void insert(ISyscallTracepoint::Ref syscall_tracepoint) override;

  virtual SuccessOrStringError
  exec(std::atomic_bool &terminate,
       void (*callback)(const ISyscallTracepoint::EventList &)) override;

protected:
  PerfEventReader(IPerfEventArray::Ref perf_event_array,
                  IBufferStorage::Ref buffer_storage);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  friend class IPerfEventReader;
};
} // namespace ebpfpub
