#include "forknamespacehelper.h"
#include "functiontracer.h"
#include "llvm_compat.h"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Verifier.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/ievent.h>
#include <tob/ebpf/llvm_utils.h>
#include <tob/ebpf/tracepointdescriptor.h>

namespace tob::ebpfpub {
namespace {
const std::string kLLVMModuleName{"ForkNamespaceHelper"};
const std::string kTracepointCategory{"sched"};
const std::string kTracepointName{"sched_process_fork"};
const std::string kParentPidFieldName{"parent_pid"};
const std::string kChildPidFieldName{"child_pid"};
const std::string kTracepointParameterTypeName{"ForkArgs"};
} // namespace

struct ForkNamespaceHelper::PrivateData final {
  tob::ebpf::IEvent::Ref sched_process_fork_event;
  utils::UniqueFd program;
};

StringErrorOr<ForkNamespaceHelper::Ref>
ForkNamespaceHelper::create(int event_map_fd) {
  try {
    return Ref(new ForkNamespaceHelper(event_map_fd));

  } catch (const StringError &error) {
    return error;

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");
  }
}

ForkNamespaceHelper::~ForkNamespaceHelper() {}

ForkNamespaceHelper::ForkNamespaceHelper(int event_map_fd)
    : d(new PrivateData) {
  auto tracepoint_event_exp =
      ebpf::IEvent::createTracepoint(kTracepointCategory, kTracepointName);

  if (!tracepoint_event_exp.succeeded()) {
    throw tracepoint_event_exp.error();
  }

  d->sched_process_fork_event = tracepoint_event_exp.takeValue();

  llvm::LLVMContext llvm_context;
  auto llvm_module_ref = ebpf::createLLVMModule(llvm_context, kLLVMModuleName);
  if (!llvm_module_ref) {
    throw StringError::create("Failed to generate the LLVM BPF module");
  }

  auto &llvm_module = *llvm_module_ref.get();
  auto success_exp = importFunctionTracerEventHeader(llvm_module);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  success_exp = createFunctionArgumentType(llvm_module);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  success_exp = generateFunction(llvm_module, event_map_fd);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Verify the module
  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  if (llvm::verifyModule(llvm_module, &error_stream) != 0) {
    error_stream.flush();

    std::string error_message = "Module verification failed";
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    throw StringError::create(error_message);
  }

  // Compile the module
  auto program_map_exp = ebpf::compileModule(llvm_module);
  if (!program_map_exp.succeeded()) {
    throw program_map_exp.error();
  }

  auto program_map = program_map_exp.takeValue();

  // Get the program and load it
  if (program_map.size() != 1U) {
    throw StringError::create("The program was not compiled");
  }

  auto &first_program = program_map.begin()->second;

  auto program_exp =
      ebpf::loadProgram(first_program, *d->sched_process_fork_event.get());

  if (!program_exp.succeeded()) {
    auto load_error =
        "The program could not be loaded: " + program_exp.error().message();

    throw StringError::create(load_error);
  }

  d->program = program_exp.takeValue();
}

SuccessOrStringError
ForkNamespaceHelper::importFunctionTracerEventHeader(llvm::Module &module) {
  return FunctionTracer::createEventHeaderType(module, false);
}

SuccessOrStringError
ForkNamespaceHelper::createFunctionArgumentType(llvm::Module &module) {
  auto tracepoint_desc_exp =
      ebpf::TracepointDescriptor::create(kTracepointCategory, kTracepointName);

  if (!tracepoint_desc_exp.succeeded()) {
    return tracepoint_desc_exp.error();
  }

  auto tracepoint_descriptor = tracepoint_desc_exp.takeValue();
  auto structure = tracepoint_descriptor->structure();
  auto &context = module.getContext();

  std::size_t current_offset{};
  std::vector<llvm::Type *> struct_type_list;

  for (const auto &field : structure) {
    if (field.name != kParentPidFieldName && field.name != kChildPidFieldName) {
      continue;
    }

    if (field.size != 4U) {
      return StringError::create(
          "Unexpected field size for parameter parent_pid/child_pid");
    }

    if (field.offset < current_offset) {
      return StringError::create(
          "Invalid field offset in the sched:sched_process_fork tracepoints "
          "format descriptor");
    }

    if (field.offset > current_offset) {
      auto padding_byte_count = field.offset - current_offset;

      auto elem_type = llvm::Type::getInt8Ty(context);
      auto array_type = llvm::ArrayType::get(elem_type, padding_byte_count);

      struct_type_list.push_back(array_type);
      current_offset += padding_byte_count;
    }

    struct_type_list.push_back(llvm::Type::getInt32Ty(context));
    current_offset += 4U;
  }

  auto type_ptr = llvm::StructType::create(struct_type_list,
                                           kTracepointParameterTypeName, true);
  if (type_ptr == nullptr) {
    return StringError::create("Failed to create the function parameter");
  }

  return {};
}

SuccessOrStringError ForkNamespaceHelper::generateFunction(llvm::Module &module,
                                                           int event_map_fd) {
  // Create the function
  auto &llvm_context = module.getContext();

  auto function_param_type =
      getTypeByName(module, kTracepointParameterTypeName);
  if (function_param_type == nullptr) {
    return StringError::create("The function argument type is not defined");
  }

  auto function_type =
      llvm::FunctionType::get(llvm::Type::getInt64Ty(llvm_context),
                              {function_param_type->getPointerTo()}, false);

  auto function_ptr =
      llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
                             "fork_namespace_helper", module);

  function_ptr->setSection("fork_namespace_helper_section");

  if (function_ptr == nullptr) {
    return StringError::create("Failed to create the module function");
  }

  function_ptr->arg_begin()->setName("args");

  // Generate the entry basic block
  llvm::IRBuilder<> builder(llvm_context);

  auto entry_bb = llvm::BasicBlock::Create(llvm_context, "entry", function_ptr);
  builder.SetInsertPoint(entry_bb);

  // Allocate the stack variables
  auto event_key_ptr =
      builder.CreateAlloca(builder.getInt64Ty(), nullptr, "event_key");

  // Create the syscall interface helper
  auto bpf_syscall_interface_exp = ebpf::BPFSyscallInterface::create(builder);
  if (!bpf_syscall_interface_exp.succeeded()) {
    return bpf_syscall_interface_exp.error();
  }

  auto bpf_syscall_interface = bpf_syscall_interface_exp.takeValue();

  // Generate the event key
  auto event_key_value = bpf_syscall_interface->getCurrentPidTgid();
  builder.CreateStore(event_key_value, event_key_ptr);

  // Read the child process id from this tracepoint event
  auto function_args = function_ptr->arg_begin();

  auto child_pid_ptr = builder.CreateGEP(
      function_args, {builder.getInt32(0), builder.getInt32(3)});

  auto child_pid = builder.CreateLoad(child_pid_ptr);
  auto child_pid_64 = builder.CreateZExt(child_pid, builder.getInt64Ty());

  // Go through each event map we received to update the event headers
  auto event_header_type = getTypeByName(module, "EventHeader");
  if (event_header_type == nullptr) {
    return StringError::create("The event header type is not defined");
  }

  // Attempt to get the event header from the map
  auto event_header_ptr = bpf_syscall_interface->mapLookupElem(
      event_map_fd, event_key_ptr, event_header_type->getPointerTo());

  auto event_header_ptr_cond = builder.CreateICmpEQ(
      event_header_ptr,
      llvm::Constant::getNullValue(event_header_ptr->getType()));

  auto valid_event_header_ptr_bb = llvm::BasicBlock::Create(
      llvm_context, "valid_event_header_ptr_fd_" + std::to_string(event_map_fd),
      function_ptr);

  auto invalid_event_header_ptr_bb = llvm::BasicBlock::Create(
      llvm_context,
      "invalid_event_header_ptr_fd_" + std::to_string(event_map_fd),
      function_ptr);

  builder.CreateCondBr(event_header_ptr_cond, invalid_event_header_ptr_bb,
                       valid_event_header_ptr_bb);

  builder.SetInsertPoint(invalid_event_header_ptr_bb);
  builder.CreateRet(builder.getInt64(0));

  builder.SetInsertPoint(valid_event_header_ptr_bb);

  // Update the exit code in the event header
  auto exit_code_ptr = builder.CreateGEP(
      event_header_ptr, {builder.getInt32(0), builder.getInt32(6)});

  builder.CreateStore(child_pid_64, exit_code_ptr);

  builder.CreateRet(builder.getInt64(0));
  return {};
}
} // namespace tob::ebpfpub
