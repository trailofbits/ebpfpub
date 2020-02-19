/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/iperfeventreader.h>

namespace tob::ebpfpub {
class PerfEventReader final : public IPerfEventReader {
public:
  virtual ~PerfEventReader() override;
  virtual void insert(IFunctionTracer::Ref syscall_tracepoint) override;

  virtual SuccessOrStringError exec(std::atomic_bool &terminate,
                                    const Callback &callback) override;

protected:
  PerfEventReader(ebpf::PerfEventArray &perf_event_array,
                  IBufferStorage &buffer_storage);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  friend class IPerfEventReader;
};
} // namespace tob::ebpfpub
