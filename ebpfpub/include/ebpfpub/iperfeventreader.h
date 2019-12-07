#pragma once

#include <atomic>
#include <memory>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/iperfeventarray.h>
#include <ebpfpub/isyscalltracepoint.h>

namespace ebpfpub {
class IPerfEventReader {
public:
  using Ref = std::shared_ptr<IPerfEventReader>;

  static StringErrorOr<Ref> create(IPerfEventArray::Ref perf_event_array,
                                   IBufferStorage::Ref buffer_storage);

  IPerfEventReader() = default;
  virtual ~IPerfEventReader() = default;

  virtual void insert(ISyscallTracepoint::Ref syscall_tracepoint) = 0;

  virtual SuccessOrStringError
  exec(std::atomic_bool &terminate,
       void (*callback)(const ISyscallTracepoint::EventList &)) = 0;

  IPerfEventReader(const IPerfEventReader &) = delete;
  IPerfEventReader &operator=(const IPerfEventReader &) = delete;
};
} // namespace ebpfpub
