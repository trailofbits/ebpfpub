#pragma once

#include "bpfoutput.h"

#include <chrono>
#include <cstdint>
#include <vector>

#include <linux/perf_event.h>

#include <ebpfpub/iperfeventarray.h>

namespace ebpfpub {
class PerfEventArray final : public IPerfEventArray {
public:
  virtual ~PerfEventArray() override;

  virtual std::size_t memoryUsage() const override;

  int fd() const;

  bool read(std::vector<std::uint8_t> &buffer,
            const std::chrono::milliseconds &timeout =
                std::chrono::milliseconds(1000U));

  PerfEventArray(const PerfEventArray &) = delete;
  PerfEventArray &operator=(const PerfEventArray &) = delete;

protected:
  PerfEventArray(std::size_t per_bpf_output_page_exponent);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  StringErrorOr<BPFOutput> createPerfBPFOutput(std::size_t processor_index,
                                               std::size_t bpf_output_size);

  using PerfBuffer = std::vector<std::uint8_t>;
  using PerfBufferList = std::vector<PerfBuffer>;

  PerfBufferList readPerfMemory(std::size_t bpf_output_index);

  friend class IPerfEventArray;
};
} // namespace ebpfpub
