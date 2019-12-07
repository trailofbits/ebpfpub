#pragma once

#include "bpfprogramwriter.h"
#include "bufferreader.h"

#include <llvm/IR/DerivedTypes.h>

#include <ebpfpub/isyscalltracepoint.h>
#include <ebpfpub/itracepointevent.h>

namespace ebpfpub {
class SyscallTracepoint final : public ISyscallTracepoint {
public:
  virtual ~SyscallTracepoint();

  virtual const std::string &syscallName() const override;
  virtual const std::string &serializerName() const override;

  virtual StringErrorOr<std::string> generateIR() const override;
  virtual std::uint32_t eventIdentifier() const override;

  StringErrorOr<EventList> parseEvents(BufferReader &buffer_reader) const;

  SuccessOrStringError start() const;
  void stop() const;

protected:
  SyscallTracepoint(const std::string &syscall_name,
                    IBufferStorage::Ref buffer_storage,
                    IPerfEventArray::Ref perf_event_array,
                    std::size_t event_map_size);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  SuccessOrStringError generateEnterFunction(BPFProgramWriter &bpf_prog_writer);

  SuccessOrStringError
  initializeExitFunction(BPFProgramWriter &bpf_prog_writer);

  SuccessOrStringError finalizeExitFunction(BPFProgramWriter &bpf_prog_writer);

  friend class ISyscallTracepoint;
};
} // namespace ebpfpub
