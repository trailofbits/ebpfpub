#include "bpfprograminstance.h"
#include "sectionmemorymanager.h"

#include <fstream>

#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace ebpfpub {
struct BPFProgramInstance::PrivateData final {
  UniqueFd program;
  UniqueFd event;
  std::string enable_switch_path;
};

StringErrorOr<BPFProgramInstance::Ref>
BPFProgramInstance::loadProgram(const BPFProgram &program,
                                const ITracepointEvent &tracepoint_event) {

  try {
    return Ref(new BPFProgramInstance(program, tracepoint_event));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

BPFProgramInstance::~BPFProgramInstance() { activateSystemTracepoint(false); }

BPFProgramInstance::BPFProgramInstance(BPFProgramInstance &&other) {
  d = std::move(other.d);
  other.d = {};
}

BPFProgramInstance &BPFProgramInstance::operator=(BPFProgramInstance &&other) {
  if (this != &other) {
    d = std::move(other.d);
    other.d = {};
  }

  return *this;
}

BPFProgramInstance::BPFProgramInstance(const BPFProgram &program,
                                       const ITracepointEvent &tracepoint_event)
    : d(new PrivateData) {

  // Get and save the path for the tracepoint's 'enable' switch
  auto enable_switch_path_exp =
      tracepoint_event.path(ITracepointEvent::PathType::EnableSwitch);

  if (!enable_switch_path_exp.succeeded()) {
    throw enable_switch_path_exp.error();
  }

  d->enable_switch_path = enable_switch_path_exp.takeValue();

  // Load the program
  union bpf_attr attr = {};
  attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
  attr.insns = reinterpret_cast<__aligned_u64>(program.data());
  attr.insn_cnt = static_cast<std::uint32_t>(program.size());
  attr.log_level = 1U;
  attr.kern_version = LINUX_VERSION_CODE;

  static const std::string kProgramLicense{"GPL"};
  attr.license = reinterpret_cast<__aligned_u64>(kProgramLicense.c_str());

  // We could in theory try to load the program with no log buffer at first, and
  // if it fails, try again with it. I prefer to call this once and have
  // everything. There's a gotcha though; if this buffer is not big enough to
  // contain the whole disasm of the program in text form, the load will fail.
  // We have a limit of 4096 instructions, so let's use a huge buffer to take
  // into account at least 4096 lines + decorations
  std::vector<char> log_buffer((4096U + 100U) * 80U);
  attr.log_buf = reinterpret_cast<__u64>(log_buffer.data());
  attr.log_size = static_cast<__u32>(log_buffer.size());

  auto program_fd =
      static_cast<int>(::syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)));

  if (program_fd < 0) {
    std::string error_message{"The program could not be loaded: "};

    const auto &log_buffer_ptr = log_buffer.data();
    if (std::strlen(log_buffer_ptr) != 0U) {
      error_message += log_buffer_ptr;
    } else {
      error_message += "No error output received from the kernel";
    }

    throw StringError::create(error_message);
  }

  auto success_exp = activateSystemTracepoint(true);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  static const int kNullPid{-1};
  static const int kNullCpu{0};
  static const int kNullGroupFd{-1};

  struct perf_event_attr perf_attr = {};
  perf_attr.type = PERF_TYPE_TRACEPOINT;
  perf_attr.size = sizeof(struct perf_event_attr);
  perf_attr.config = tracepoint_event.eventIdentifier();
  perf_attr.sample_period = 1;
  perf_attr.sample_type = PERF_SAMPLE_RAW;
  perf_attr.wakeup_events = 1;
  perf_attr.disabled = 1;

  auto event_fd =
      static_cast<int>(::syscall(__NR_perf_event_open, &perf_attr, kNullPid,
                                 kNullCpu, kNullGroupFd, PERF_FLAG_FD_CLOEXEC));

  if (event_fd == -1) {
    throw StringError::create("Failed to create the perf output");
  }

  if (ioctl(event_fd, PERF_EVENT_IOC_SET_BPF, program_fd) < 0) {
    throw StringError::create(
        "Failed to attach the perf output to the BPF program");
  }

  if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    throw StringError::create("Failed to enable the perf output");
  }

  d->event.reset(event_fd);
  d->program.reset(program_fd);
}

SuccessOrStringError BPFProgramInstance::activateSystemTracepoint(bool enable) {
  std::fstream f(d->enable_switch_path, std::ios::out | std::ios::binary);

  if (!f) {
    return StringError::create("Failed to open the 'enable' switch file");
  }

  f << (enable ? '1' : '0');
  if (!f) {
    return StringError::create("Failed to write to the 'enable' switch file");
  }

  return {};
}

StringErrorOr<BPFProgramSet> compileModule(llvm::Module &original_module) {
  auto module = llvm::CloneModule(original_module);

  auto exec_engine_builder =
      std::make_unique<llvm::EngineBuilder>(std::move(module));

  exec_engine_builder->setMArch("bpf");
  exec_engine_builder->setUseOrcMCJITReplacement(false);
  exec_engine_builder->setOptLevel(llvm::CodeGenOpt::Default);

  std::string builder_err_output;
  exec_engine_builder->setErrorStr(&builder_err_output);

  MemorySectionMap section_map;
  exec_engine_builder->setMCJITMemoryManager(
      std::make_unique<SectionMemoryManager>(section_map));

  std::unique_ptr<llvm::ExecutionEngine> execution_engine(
      exec_engine_builder->create());

  if (execution_engine == nullptr) {
    std::string error_message = "Failed to create the execution engine builder";
    if (!builder_err_output.empty()) {
      error_message += ": " + builder_err_output;
    }

    return StringError::create(error_message);
  }

  execution_engine->setProcessAllSections(true);
  execution_engine->finalizeObject();

  BPFProgramSet bpf_program_set;

  for (const auto &p : section_map) {
    auto section_name = p.first;
    auto bytecode_buffer = p.second.data;

    if (section_name.empty() || section_name[0] == '.') {
      continue;
    }

    BPFProgram program = {};
    auto instruction_count = bytecode_buffer.size() / sizeof(struct bpf_insn);

    for (std::size_t i = 0U; i < instruction_count; ++i) {
      struct bpf_insn instruction = {};

      auto source_ptr = bytecode_buffer.data() + (i * sizeof(struct bpf_insn));
      std::memcpy(&instruction, source_ptr, sizeof(instruction));

      program.push_back(instruction);
    }

    bpf_program_set.insert({section_name, std::move(program)});
  }

  if (bpf_program_set.size() != 2U) {
    return StringError::create("Invalid program count: " +
                               std::to_string(bpf_program_set.size()));
  }

  return bpf_program_set;
}
} // namespace ebpfpub
