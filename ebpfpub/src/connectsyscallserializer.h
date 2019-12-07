#pragma once

#include "isyscallserializer.h"

#include <memory>

namespace ebpfpub {
class ConnectSyscallSerializer final : public ISyscallSerializer {
public:
  ConnectSyscallSerializer();
  virtual ~ConnectSyscallSerializer() override;

  virtual const std::string &name() const override;

  virtual SuccessOrStringError
  generate(const ITracepointEvent &enter_event,
           BPFProgramWriter &bpf_prog_writer) override;

  virtual SuccessOrStringError
  parseEvents(ISyscallTracepoint::Event &event, BufferReader &buffer_reader,
              BufferStorage &buffer_storage) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace ebpfpub
