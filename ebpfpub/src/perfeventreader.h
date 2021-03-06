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
  virtual void insert(IFunctionTracer::Ref function_tracer) override;

  virtual SuccessOrStringError exec(const std::chrono::seconds &timeout,
                                    Callback callback) override;

protected:
  PerfEventReader(ebpf::PerfEventArray &perf_event_array);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  friend class IPerfEventReader;
};
} // namespace tob::ebpfpub
