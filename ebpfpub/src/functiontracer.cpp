/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "functiontracer.h"
#include "abi.h"
#include "forknamespacehelper.h"

#include <iostream>
#include <limits>
#include <unordered_set>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Verifier.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/iperfevent.h>
#include <tob/ebpf/llvm_utils.h>
#include <tob/ebpf/tracepointdescriptor.h>

namespace tob::ebpfpub {
namespace {
const std::string kSpecialExitCodeParameterName{"EXIT_CODE"};
const std::string kLLVMModuleName{"FunctionTracer"};
const std::string kEventTypeName{"Event"};
const std::string kEventHeaderTypeName{"EventHeader"};
const std::string kEventDataTypeName{"EventData"};
const std::string kEnterFunctionParameterTypeName{"EnterFunctionParameters"};
const std::string kExitFunctionParameterTypeName{"ExitFunctionParameters"};
const std::string kEnterFunctionName{"onFunctionEnter"};
const std::string kExitFunctionName{"onFunctionExit"};

std::string
stringFromBufferData(const FunctionTracer::Event::Field::Buffer &buffer) {
  auto buffer_begin = buffer.data();
  auto buffer_end = buffer.data() + buffer.size();

  auto terminator = std::find(buffer_begin, buffer_end, 0x00);
  if (terminator == buffer_end) {
    terminator = buffer_end - 1;
  }

  auto string_size = static_cast<std::size_t>(terminator - buffer_begin);

  std::string string_value;
  string_value.resize(string_size);
  std::memcpy(&string_value[0], buffer_begin, string_size);

  return string_value;
}
} // namespace

struct FunctionTracer::PrivateData final {
  PrivateData(IBufferStorage &buffer_storage_,
              ebpf::PerfEventArray &perf_event_array_)
      : buffer_storage(buffer_storage_), perf_event_array(perf_event_array_) {}

  std::string name;

  ParameterList parameter_list;
  ParameterListIndex parameter_list_index;

  std::string module_ir;

  IBufferStorage &buffer_storage;
  ebpf::PerfEventArray &perf_event_array;

  ebpf::IPerfEvent::Ref enter_event;
  ebpf::IPerfEvent::Ref exit_event;

  EventMap::Ref event_map;
  EventScratchSpace::Ref event_scratch_space;

  utils::UniqueFd enter_program;
  utils::UniqueFd exit_program;

  ForkNamespaceHelper::Ref fork_ns_helper;
};

FunctionTracer::~FunctionTracer() {}

const std::string &FunctionTracer::name() const { return d->name; }

std::uint64_t FunctionTracer::eventIdentifier() const {
  return static_cast<std::uint64_t>(d->enter_event->fd());
}

std::string FunctionTracer::ir() const { return d->module_ir; }

StringErrorOr<FunctionTracer::EventList>
FunctionTracer::parseEventData(BufferReader &buffer_reader) const {

  auto event_object_size =
      static_cast<std::uint32_t>(d->event_map->valueSize());

  auto event_data_exp = parseEventData(
      buffer_reader, event_object_size, eventIdentifier(), name(),
      d->parameter_list, d->parameter_list_index, d->buffer_storage);

  return event_data_exp;
}

FunctionTracer::FunctionTracer(
    const std::string &name, const ParameterList &parameter_list,
    std::size_t event_map_size, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, ebpf::IPerfEvent::Ref enter_event,
    ebpf::IPerfEvent::Ref exit_event, OptionalPidList excluded_processes)
    : d(new PrivateData(buffer_storage, perf_event_array)) {

  d->name = name;
  d->parameter_list = parameter_list;

  d->enter_event = std::move(enter_event);
  d->exit_event = std::move(exit_event);

  auto success_exp = validateParameterList(parameter_list, buffer_storage);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Create the parameter list index, mapping the `in` and `out` parameters of
  // the function to the event data structure. It doesn't matter which event we
  // use (enter/exit) as they will always be both of the same type (tracepoint,
  // kprobe or uprobe)

  bool is_tracepoint =
      d->enter_event->type() == ebpf::IPerfEvent::Type::Tracepoint;

  auto param_list_index_exp =
      createParameterListIndex(is_tracepoint, parameter_list);

  if (!param_list_index_exp.succeeded()) {
    throw param_list_index_exp.error();
  }

  d->parameter_list_index = param_list_index_exp.takeValue();

  llvm::LLVMContext llvm_context;
  auto llvm_module_ref = ebpf::createLLVMModule(llvm_context, kLLVMModuleName);
  if (!llvm_module_ref) {
    throw StringError::create("Failed to generate the LLVM BPF module");
  }

  auto &llvm_module = *llvm_module_ref.get();
  success_exp = createEventHeaderType(llvm_module);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  success_exp = createEventDataType(llvm_module, parameter_list);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  success_exp = createEventType(llvm_module);
  if (success_exp.failed()) {
    throw success_exp.error();
  }

  auto event_map_exp = createEventMap(llvm_module, event_map_size);
  if (!event_map_exp.succeeded()) {
    throw event_map_exp.error();
  }

  d->event_map = event_map_exp.takeValue();

  auto event_scratch_space_exp = createEventScratchSpace(llvm_module);
  if (!event_scratch_space_exp.succeeded()) {
    throw event_scratch_space_exp.error();
  }

  d->event_scratch_space = event_scratch_space_exp.takeValue();

  // Create the enter function parameters
  success_exp = createEnterFunctionArgumentType(
      llvm_module, *d->enter_event.get(), parameter_list);

  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Create the exit function parameters
  success_exp =
      createExitFunctionArgumentType(llvm_module, *d->exit_event.get());

  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Assemble the enter function
  auto &event_map_ref = *d->event_map.get();
  auto &event_scratch_space_ref = *d->event_scratch_space.get();

  success_exp = createEnterFunction(
      llvm_module, event_map_ref, event_scratch_space_ref,
      *d->enter_event.get(), parameter_list, d->parameter_list_index,
      d->buffer_storage, excluded_processes);

  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Assemble the exit function; if this is a fork syscall, ask the
  // createExitFunction method to *NOT* update the exit code
  // automatically
  auto create_fork_ns_helper =
      d->name == "fork" || d->name == "vfork" || d->name == "clone";

  success_exp = createExitFunction(llvm_module, event_map_ref,
                                   *d->exit_event.get(), parameter_list,
                                   d->parameter_list_index, d->buffer_storage,
                                   d->perf_event_array, create_fork_ns_helper);

  if (success_exp.failed()) {
    throw success_exp.error();
  }

  // Save the module IR
  llvm::raw_string_ostream output_stream(d->module_ir);
  llvm_module.print(output_stream, nullptr);

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

  // Compile the module; we'll obtain one program for the enter event, and
  // another one for the exit event
  auto program_map_exp = ebpf::compileModule(llvm_module);
  if (!program_map_exp.succeeded()) {
    throw program_map_exp.error();
  }

  auto program_map = program_map_exp.takeValue();

  // Get the enter program
  auto enter_program_it = program_map.find("onFunctionEnter_section");
  if (enter_program_it == program_map.end()) {
    throw StringError::create("The enter program was not compiled");
  }

  auto enter_program = enter_program_it->second;

  // Get the exit program
  auto exit_program_it = program_map.find("onFunctionExit_section");
  if (exit_program_it == program_map.end()) {
    throw StringError::create("The exit program was not compiled");
  }

  auto exit_program = exit_program_it->second;

  // Load the enter program
  auto program_exp = ebpf::loadProgram(enter_program, *d->enter_event.get());

  if (!program_exp.succeeded()) {
    auto load_error = "The 'enter' program could not be loaded: " +
                      program_exp.error().message();

    throw StringError::create(load_error);
  }

  d->enter_program = program_exp.takeValue();

  // Load the exit program
  program_exp = ebpf::loadProgram(exit_program, *d->exit_event.get());

  if (!program_exp.succeeded()) {
    auto load_error = "The 'exit' program could not be loaded: " +
                      program_exp.error().message();

    throw StringError::create(load_error);
  }

  d->exit_program = program_exp.takeValue();

  // Create the fork namespace helper if required
  if (create_fork_ns_helper) {
    auto fork_ns_helper_exp = ForkNamespaceHelper::create(d->event_map->fd());
    if (!fork_ns_helper_exp.succeeded()) {
      throw fork_ns_helper_exp.error();
    }

    d->fork_ns_helper = fork_ns_helper_exp.takeValue();
  }
}

StringErrorOr<llvm::Value *>
FunctionTracer::getStackAllocation(const StackAllocationList &allocation_list,
                                   const std::string &name) {

  auto allocation_it = allocation_list.find(name);
  if (allocation_it == allocation_list.end()) {
    return StringError::create("The stack variable named '" + name +
                               "' was not found");
  }

  const auto &allocation = allocation_it->second;
  return allocation;
}

SuccessOrStringError FunctionTracer::allocateStackSpace(
    StackAllocationList &allocation_list, const std::string &name,
    llvm::IRBuilder<> &builder, llvm::Type *allocation_type) {

  auto allocation_it = allocation_list.find(name);
  if (allocation_it != allocation_list.end()) {
    return StringError::create(
        "An allocation with the same name already exists");
  }

  auto value = builder.CreateAlloca(allocation_type);
  allocation_list.insert({name, value});

  return {};
}

StringErrorOr<FunctionTracer::ParameterListIndex>
FunctionTracer::createParameterListIndex(
    bool is_tracepoint, const FunctionTracer::ParameterList &valid_param_list) {

  // If this is a tracepoint, we will have to skip its header (i.e.:
  // common_type, common_flags, etc...) when accessing its data through the
  // `args` structure
  std::size_t base_source_index{0U};
  if (is_tracepoint) {
    base_source_index = 5U;
  }

  // Keep track of the current destination index, since we may have expanded
  // InOut parameters
  ParameterListIndex index;

  std::size_t current_destination_index{0U};
  for (auto param_it = valid_param_list.begin();
       param_it != valid_param_list.end(); ++param_it) {

    ParameterListIndexEntry entry = {};
    entry.param_index =
        static_cast<std::size_t>(param_it - valid_param_list.begin());

    entry.source_index =
        base_source_index + static_cast<std::uint32_t>(entry.param_index);

    const auto &param = *param_it;
    if (param.mode == Parameter::Mode::In ||
        param.mode == Parameter::Mode::InOut) {

      entry.destination_index_in_opt = current_destination_index;
      ++current_destination_index;
    }

    if (param.mode == Parameter::Mode::Out ||
        param.mode == Parameter::Mode::InOut) {

      entry.destination_index_out_opt = current_destination_index;
      ++current_destination_index;
    }

    index.push_back(entry);
  }

  // clang-format off
  std::sort(
    index.begin(),
    index.end(),

    [valid_param_list](const ParameterListIndexEntry &lhs,
                       const ParameterListIndexEntry &rhs) -> bool {

      auto L_compareParameterModes = [](Parameter::Mode l,
                                       Parameter::Mode r) -> bool {

        // Do not depend on the order of declaration of the enum values
        auto L_parameterModeValue = [](Parameter::Mode mode) -> std::size_t {
          switch (mode) {
          case Parameter::Mode::In:
            return 0;

          case Parameter::Mode::InOut:
            return 1;

          case Parameter::Mode::Out:
            return 2;

          default:
            throw std::logic_error("Invalid capture mode");
          }
        };
        
        return L_parameterModeValue(l) < L_parameterModeValue(r);
      };

      auto L_compareParameterTypes = [](Parameter::Type l,
                                        Parameter::Type r) -> bool {

        // Do not depend on the order of declaration of the enum values
        auto L_parameterTypeValue = [](Parameter::Type type) -> std::size_t {
          switch (type) {
          case Parameter::Type::Integer:
            return 0;

          case Parameter::Type::IntegerPtr:
            return 1;

          case Parameter::Type::String:
            return 2;

          case Parameter::Type::Buffer:
            return 3;

          case Parameter::Type::Argv:
            return 4;

          default:
            throw std::logic_error("Invalid parameter type");
          }
        };

        return L_parameterTypeValue(l) < L_parameterTypeValue(r);
      };

      auto L_compareOptSizeVariant = [](const Parameter::SizeVariant &l,
                                        const Parameter::SizeVariant &) -> bool {

        return std::holds_alternative<std::size_t>(l);
      };

      const auto &lhs_parameter = valid_param_list.at(lhs.param_index);
      const auto &rhs_parameter = valid_param_list.at(rhs.param_index);

      if (lhs_parameter.type != rhs_parameter.type) {
        return L_compareParameterTypes(lhs_parameter.type, rhs_parameter.type);
      }

      if (lhs_parameter.mode != rhs_parameter.mode) {
        return L_compareParameterModes(lhs_parameter.mode, rhs_parameter.mode);
      }

      if (lhs_parameter.opt_size_var.has_value() != rhs_parameter.opt_size_var.has_value()) {
        if (lhs_parameter.opt_size_var.has_value()) {
          return false;

        } else {
          return true;
        }
      }

      // At this point, the two ::has_value() are equal
      if (lhs_parameter.opt_size_var.has_value()) {
        const auto &lhs_size_var = lhs_parameter.opt_size_var.value();
        const auto &rhs_size_var = rhs_parameter.opt_size_var.value();

        if (lhs_size_var.index() != rhs_size_var.index()) {
          return L_compareOptSizeVariant(lhs_size_var, rhs_size_var);
        }
      }

      return lhs_parameter.name < rhs_parameter.name;
    }
  );
  // clang-format on

  return index;
}

StringErrorOr<llvm::Value *>
FunctionTracer::getVariable(const VariableList &variable_list,
                            const std::string &name) {

  auto variable_it = variable_list.find(name);
  if (variable_it == variable_list.end()) {
    return StringError::create("No following variable was not found: '" + name +
                               "'");
  }

  auto variable = variable_it->second;
  return variable;
}

SuccessOrStringError FunctionTracer::saveVariable(VariableList &variable_list,
                                                  const std::string &name,
                                                  llvm::Value *value) {
  auto variable_it = variable_list.find(name);
  if (variable_it != variable_list.end()) {
    return StringError::create("The following variable already exists: '" +
                               name + "'");
  }

  variable_list.insert({name, value});
  return {};
}

StringErrorOr<llvm::Value *>
FunctionTracer::generateBufferStorageIndex(llvm::IRBuilder<> &builder,
                                           const VariableList &variable_list,
                                           IBufferStorage &buffer_storage) {

  auto buffer_storage_index_generator_exp =
      getVariable(variable_list, "buffer_storage_index_generator");

  if (!buffer_storage_index_generator_exp.succeeded()) {
    return buffer_storage_index_generator_exp.error();
  }

  auto buffer_storage_index_generator =
      buffer_storage_index_generator_exp.takeValue();

  auto previous_buffer_storage_index =
      builder.CreateLoad(buffer_storage_index_generator);

  auto buffer_storage_index =
      builder.CreateBinOp(llvm::Instruction::Add, previous_buffer_storage_index,
                          builder.getInt32(1));

  auto buffer_storage_count =
      static_cast<std::uint32_t>(buffer_storage.bufferCount());

  buffer_storage_index =
      builder.CreateBinOp(llvm::Instruction::URem, buffer_storage_index,
                          builder.getInt32(buffer_storage_count));

  builder.CreateStore(buffer_storage_index, buffer_storage_index_generator);

  return buffer_storage_index;
}

llvm::Value *FunctionTracer::tagBufferStorageIndex(
    ebpf::BPFSyscallInterface &bpf_syscall_interface,
    llvm::IRBuilder<> &builder, llvm::Value *buffer_storage_index) {

  auto current_processor_id = bpf_syscall_interface.getSmpProcessorId();

  current_processor_id =
      builder.CreateZExt(current_processor_id, builder.getInt64Ty());

  current_processor_id = builder.CreateBinOp(
      llvm::Instruction::Shl, current_processor_id, builder.getInt64(48U));

  current_processor_id =
      builder.CreateBinOp(llvm::Instruction::Or, current_processor_id,
                          builder.getInt64(0xFF00000000000000ULL));

  auto tagged_buffer_storage_index =
      builder.CreateZExt(buffer_storage_index, builder.getInt64Ty());

  tagged_buffer_storage_index = builder.CreateBinOp(
      llvm::Instruction::Or, tagged_buffer_storage_index, current_processor_id);

  return tagged_buffer_storage_index;
}

SuccessOrStringError FunctionTracer::validateParameterList(
    const FunctionTracer::ParameterList &parameter_list,
    IBufferStorage &buffer_storage) {

  std::unordered_set<std::string> valid_integer_list;
  std::unordered_set<std::string> parameter_name_list;

  for (auto param_it = parameter_list.begin(); param_it != parameter_list.end();
       ++param_it) {
    const auto &param = *param_it;

    // Make sure the parameter name does not contain the special separator
    // that we use internally
    if (param.name.find(':') != std::string::npos) {
      return StringError::create("Invalid parameter name");
    }

    // Don't duplicate parameter names
    if (parameter_name_list.count(param.name) > 0U) {
      return StringError::create(
          "Duplicated name found in the given parameter list");
    }

    parameter_name_list.insert(param.name);

    // The function exit code can be re-captured explicitly using
    // a custom type. This is done using the `EXIT_CODE` variable
    // name, and it must be set as an OUT parameter
    if (param.name == kSpecialExitCodeParameterName) {
      if (param.mode != Parameter::Mode::Out) {
        return StringError::create(
            "The special 'EXIT_CODE' parameter can only be set as OUT");
      }

      // This has to be the last argument since otherwise it will
      // cause the indexes to out of sync with the real parameters
      if (std::next(param_it) != parameter_list.end()) {
        return StringError::create(
            "The special 'EXIT_CODE' parameter has to be specified last");
      }
    }

    // Validate the type
    if (param.type == Parameter::Type::Integer ||
        param.type == Parameter::Type::IntegerPtr) {

      auto is_integer_ptr = (param.type == Parameter::Type::IntegerPtr);

      if (!param.opt_size_var.has_value()) {
        return StringError::create("Missing field size type for '" +
                                   param.name + "'");
      }

      const auto &size_var = param.opt_size_var.value();

      if (!std::holds_alternative<std::size_t>(size_var)) {
        return StringError::create("Invalid field size type for '" +
                                   param.name + "'");
      }

      const auto &integer_size = std::get<std::size_t>(size_var);

      switch (integer_size) {
      case 1U:
      case 2U:
      case 4U:
      case 8U:
        break;

      default: {
        return StringError::create("Invalid field size specified for '" +
                                   param.name + "'");
      }
      }

      if (is_integer_ptr) {
        if (param.mode == Parameter::Mode::In ||
            param.mode == Parameter::Mode::InOut) {
          valid_integer_list.insert("in:" + param.name);
        }

        if (param.mode == Parameter::Mode::Out ||
            param.mode == Parameter::Mode::InOut) {
          valid_integer_list.insert("out:" + param.name);
        }

      } else {
        if (param.mode != Parameter::Mode::In) {
          return StringError::create("Integer fields can only be set as IN");
        }

        valid_integer_list.insert("in:" + param.name);
      }

    } else if (param.type == Parameter::Type::String) {
      if (param.opt_size_var.has_value()) {
        return StringError::create(
            "String types should not have a size attribute");
      }

    } else if (param.type == Parameter::Type::Argv) {
      if (param.mode != Parameter::Mode::In) {
        return StringError::create("Argv fields can only be set as IN");
      }

      if (!param.opt_size_var.has_value()) {
        return StringError::create(
            "Missing field size for the following Argv parameter: " +
            param.name);
      }

      if (!std::holds_alternative<std::size_t>(param.opt_size_var.value())) {
        return StringError::create(
            "Invalid field size for the following Argv parameter: " +
            param.name);
      }

      auto argv_size = std::get<std::size_t>(param.opt_size_var.value());
      if (argv_size == 0) {
        return StringError::create(
            "The field size for the Argv parameter named '" + param.name +
            "' is set to 0");
      }

      // Assuming that we need 64-bit pointers for each string, make sure we
      // have enough space into a single buffer storage entry to save the
      // requested amount of entries
      auto index_space = (argv_size + 1U) * sizeof(std::uint64_t);
      if (index_space >= buffer_storage.bufferSize()) {
        return StringError::create("The buffer storage entry size is too small "
                                   "to store the Argv indexes of parameter " +
                                   param.name);
      }

      // Also make sure that the argv_size value makes sense according to the
      // number of buffer entries we have. This is hard to validate in a
      // meaningful way, but as a general rule let's throw an error if the
      // current settings wouldn't allow us to store at least two events
      // without losing data
      if (argv_size * 2U >= buffer_storage.bufferCount()) {
        return StringError::create(
            "The buffer storage entry count is too small to store the amount "
            "of Argv entries specified for parameter " +
            param.name);
      }

    } else if (param.type == Parameter::Type::Buffer) {
      continue;

    } else {
      return StringError::create("Unsupported parameter type specified for '" +
                                 param.name + "'");
    }
  }

  for (const auto &param : parameter_list) {
    if (param.type != Parameter::Type::Buffer) {
      continue;
    }

    if (!param.opt_size_var.has_value()) {
      return StringError::create("Missing field size type for '" + param.name +
                                 "'");
    }

    const auto &size_var = param.opt_size_var.value();

    if (std::holds_alternative<std::size_t>(size_var)) {
      const auto &integer_size = std::get<std::size_t>(size_var);
      if (integer_size == 0) {
        return StringError::create("Invalid field size specified for '" +
                                   param.name + "'");
      }

    } else if (std::holds_alternative<std::string>(size_var)) {
      std::vector<std::string> prefix_list;

      if (param.mode == Parameter::Mode::In ||
          param.mode == Parameter::Mode::InOut) {

        prefix_list.push_back("in:");
      }

      if (param.mode == Parameter::Mode::Out ||
          param.mode == Parameter::Mode::InOut) {

        prefix_list.push_back("out:");
      }

      auto size_param_name = std::get<std::string>(size_var);

      for (const auto &prefix : prefix_list) {
        auto full_size_param_name = prefix + size_param_name;

        if (valid_integer_list.count(full_size_param_name) == 0) {
          return StringError::create("Invalid field size specified for '" +
                                     param.name + "'");
        }
      }

    } else {
      return StringError::create("Unexpected field size type specified for '" +
                                 param.name + "'");
    }
  }

  return {};
}

llvm::Type *FunctionTracer::llvmTypeForMemoryPointer(llvm::Module &module) {
  auto &context = module.getContext();

  llvm::Type *llvm_type{nullptr};
  if (sizeof(void *) == 4U) {
    llvm_type = llvm::Type::getInt32Ty(context);
  } else {
    llvm_type = llvm::Type::getInt64Ty(context);
  }

  return llvm_type;
}

SuccessOrStringError
FunctionTracer::createEventHeaderType(llvm::Module &module) {
  auto &context = module.getContext();

  // clang-format off
  std::vector<llvm::Type *> type_list = {
    // Event object size
    llvm::Type::getInt32Ty(context),

    // Event identifier
    llvm::Type::getInt64Ty(context),

    // Timestamp
    llvm::Type::getInt64Ty(context),

    // PID, TGID
    llvm::Type::getInt64Ty(context),

    // UID, GID
    llvm::Type::getInt64Ty(context),

    // cgroup id
    llvm::Type::getInt64Ty(context),

    // Exit code
    llvm::Type::getInt64Ty(context),

    // Probe error flag
    llvm::Type::getInt64Ty(context),

    // Call duration
    llvm::Type::getInt64Ty(context)
  };
  // clang-format on

  auto existing_type_ptr = module.getTypeByName(kEventHeaderTypeName);
  if (existing_type_ptr != nullptr) {
    return StringError::create("A type named " + kEventHeaderTypeName +
                               " is already defined");
  }

  auto event_header =
      llvm::StructType::create(type_list, kEventHeaderTypeName, true);

  if (event_header == nullptr) {
    return StringError::create("Failed to create the event header type");
  }

  return {};
}

SuccessOrStringError
FunctionTracer::createEventDataType(llvm::Module &module,
                                    const ParameterList &valid_param_list) {

  if (valid_param_list.empty()) {
    return {};
  }

  auto &context = module.getContext();

  std::vector<llvm::Type *> type_list;

  for (const auto &param : valid_param_list) {
    llvm::Type *field_type{nullptr};

    switch (param.type) {
    case Parameter::Type::Integer:
    case Parameter::Type::IntegerPtr:
    case Parameter::Type::Buffer:
    case Parameter::Type::String:
    case Parameter::Type::Argv:
      field_type = llvm::Type::getInt64Ty(context);
      break;
    }

    if (field_type == nullptr) {
      return StringError::create("Invalid parameter type");
    }

    type_list.push_back(field_type);
    if (param.mode == Parameter::Mode::InOut) {
      type_list.push_back(field_type);
    }
  }

  auto existing_type_ptr = module.getTypeByName(kEventDataTypeName);
  if (existing_type_ptr != nullptr) {
    return StringError::create("A type named " + kEventDataTypeName +
                               " is already defined");
  }

  auto event_data_type =
      llvm::StructType::create(type_list, kEventDataTypeName, true);

  if (event_data_type == nullptr) {
    return StringError::create("Failed to create the event data type");
  }

  return {};
}

SuccessOrStringError FunctionTracer::createEventType(llvm::Module &module) {
  auto event_header_type = module.getTypeByName(kEventHeaderTypeName);
  if (event_header_type == nullptr) {
    return StringError::create("The event header type is not defined");
  }

  std::vector<llvm::Type *> type_list = {event_header_type};

  auto event_data_type = module.getTypeByName(kEventDataTypeName);
  if (event_data_type != nullptr) {
    type_list.push_back(event_data_type);
  }

  auto event_type = llvm::StructType::create(type_list, kEventTypeName, true);

  if (event_type == nullptr) {
    return StringError::create("Failed to create the event type");
  }

  return {};
}

StringErrorOr<FunctionTracer::EventMap::Ref>
FunctionTracer::createEventMap(llvm::Module &module,
                               std::size_t event_map_size) {

  auto event_type = module.getTypeByName(kEventTypeName);
  if (event_type == nullptr) {
    return StringError::create("The event type is not defined");
  }

  auto event_type_size = ebpf::getLLVMStructureSize(event_type, &module);
  return EventMap::create(event_type_size, event_map_size);
}

StringErrorOr<FunctionTracer::EventScratchSpace::Ref>
FunctionTracer::createEventScratchSpace(llvm::Module &module) {

  auto event_type = module.getTypeByName(kEventTypeName);
  if (event_type == nullptr) {
    return StringError::create("The event type is not defined");
  }

  auto event_type_size = ebpf::getLLVMStructureSize(event_type, &module);
  return EventScratchSpace::create(event_type_size, 1U);
}

SuccessOrStringError FunctionTracer::createEnterFunctionArgumentType(
    llvm::Module &module, ebpf::IPerfEvent &enter_event,
    const ParameterList &parameter_list) {

  auto &context = module.getContext();

  StringErrorOr<llvm::StructType *> function_param_type_exp;

  if (enter_event.type() == ebpf::IPerfEvent::Type::Tracepoint) {
    // TODO(alessandro): We could future-proof this by importing
    // the header from a real tracepoint

    // Tracepoints always start with a common header
    std::vector<llvm::Type *> type_list;

    // field:unsigned short common_type; offset:0; size:2;
    // signed:0;
    type_list.push_back(llvm::Type::getInt16Ty(context));

    // field:unsigned char common_flags; offset:2; size:1;
    // signed:0;
    type_list.push_back(llvm::Type::getInt8Ty(context));

    // field:unsigned char common_preempt_count; offset:3;
    // size:1; signed:0;
    type_list.push_back(llvm::Type::getInt8Ty(context));

    // field:int common_pid; offset:4; size:4; signed:1;
    type_list.push_back(llvm::Type::getInt32Ty(context));

    // field:int __syscall_nr; offset:8; size:4; signed:1;
    type_list.push_back(llvm::Type::getInt32Ty(context));

    // The rest of the parameters follow
    for (const auto &param : parameter_list) {
      llvm::Type *field_type{nullptr};

      // Skip the special "EXIT_CODE" parameter, if defined
      if (param.name == kSpecialExitCodeParameterName) {
        continue;
      }

      switch (param.type) {
      case Parameter::Type::Integer: {
        const auto size = std::get<std::size_t>(param.opt_size_var.value());

        switch (size) {
        case 1U:
          field_type = llvm::Type::getInt8Ty(context);
          break;

        case 2U:
          field_type = llvm::Type::getInt16Ty(context);
          break;

        case 4U:
          field_type = llvm::Type::getInt32Ty(context);
          break;

        case 8U:
          field_type = llvm::Type::getInt64Ty(context);
          break;
        }

        break;
      }

      case Parameter::Type::IntegerPtr:
      case Parameter::Type::Buffer:
      case Parameter::Type::String:
      case Parameter::Type::Argv:
        field_type = llvmTypeForMemoryPointer(module);
        break;
      }

      type_list.push_back(field_type);
    }

    auto type_ptr = llvm::StructType::create(
        type_list, kEnterFunctionParameterTypeName, false);

    if (type_ptr == nullptr) {
      function_param_type_exp =
          StringError::create("Failed to create the enter function parameter");

    } else {
      function_param_type_exp = type_ptr;
    }

  } else {
    // u(ret)probes and k(ret)probes only use the pt_regs structure
    function_param_type_exp =
        ebpf::getPtRegsStructure(module, kEnterFunctionParameterTypeName);
  }

  if (!function_param_type_exp.succeeded()) {
    return function_param_type_exp.error();
  }

  return {};
}

SuccessOrStringError
FunctionTracer::createExitFunctionArgumentType(llvm::Module &module,
                                               ebpf::IPerfEvent &exit_event) {

  auto &context = module.getContext();

  StringErrorOr<llvm::StructType *> function_param_type_exp;

  if (exit_event.type() == ebpf::IPerfEvent::Type::Tracepoint) {
    // TODO(alessandro): We could future-proof this by importing
    // the header from a real tracepoint
    std::vector<llvm::Type *> type_list;

    // field:unsigned short common_type; offset:0; size:2;
    // signed:0;
    type_list.push_back(llvm::Type::getInt16Ty(context));

    // field:unsigned char common_flags; offset:2; size:1;
    // signed:0;
    type_list.push_back(llvm::Type::getInt8Ty(context));

    // field:unsigned char common_preempt_count; offset:3;
    // size:1;signed:0;
    type_list.push_back(llvm::Type::getInt8Ty(context));

    // field:int common_pid; offset:4; size:4; signed:1;
    type_list.push_back(llvm::Type::getInt32Ty(context));

    // field:int __syscall_nr; offset:8; size:4; signed:1;
    type_list.push_back(llvm::Type::getInt32Ty(context));

    // field:long ret; offset:16; size:8; signed:1;
    type_list.push_back(llvmTypeForMemoryPointer(module));

    auto type_ptr = llvm::StructType::create(
        type_list, kExitFunctionParameterTypeName, false);

    if (type_ptr == nullptr) {
      function_param_type_exp =
          StringError::create("Failed to create the enter function parameter");

    } else {
      function_param_type_exp = type_ptr;
    }

  } else {
    // u(ret)probes and {k,u}(ret)probes only use the pt_regs structure
    function_param_type_exp =
        ebpf::getPtRegsStructure(module, kExitFunctionParameterTypeName);
  }

  if (!function_param_type_exp.succeeded()) {
    return function_param_type_exp.error();
  }

  return {};
}

StringErrorOr<llvm::Value *> FunctionTracer::getMapEntry(
    int fd, llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface,
    const StackAllocationList &allocation_list, llvm::Value *map_index_value,
    llvm::Type *map_entry_type, const std::string &label) {

  auto current_bb = builder.GetInsertBlock();
  auto &context = current_bb->getContext();
  auto current_function = current_bb->getParent();

  // Create a new basic block
  current_bb = llvm::BasicBlock::Create(
      context, "acquire_" + label + "map_entry", current_function);

  builder.CreateBr(current_bb);
  builder.SetInsertPoint(current_bb);

  // Acquire a suitable map index and initialize it
  auto large_index = (map_index_value->getType() == builder.getInt64Ty());
  auto index_name =
      (large_index ? "generic_map_index_64" : "generic_map_index_32");

  auto map_index_exp = getStackAllocation(allocation_list, index_name);
  if (!map_index_exp.succeeded()) {
    return map_index_exp.error();
  }

  auto map_index = map_index_exp.takeValue();
  builder.CreateStore(map_index_value, map_index);

  // Acquire the map entry
  auto map_entry =
      bpf_syscall_interface.mapLookupElem(fd, map_index, map_entry_type);

  // Terminate the function if the entry was not found
  auto map_entry_cond = builder.CreateICmpEQ(
      llvm::Constant::getNullValue(map_entry->getType()), map_entry);

  auto invalid_map_entry_bb = llvm::BasicBlock::Create(
      context, "invalid_" + label + "map_entry", current_function);

  auto valid_map_entry_bb = llvm::BasicBlock::Create(
      context, "valid_" + label + "map_entry", current_function);

  builder.CreateCondBr(map_entry_cond, invalid_map_entry_bb,
                       valid_map_entry_bb);

  builder.SetInsertPoint(invalid_map_entry_bb);
  builder.CreateRet(builder.getInt64(0));

  builder.SetInsertPoint(valid_map_entry_bb);

  return map_entry;
}

SuccessOrStringError FunctionTracer::createEnterFunction(
    llvm::Module &module, EventMap &event_map,
    EventScratchSpace &event_scratch_space, ebpf::IPerfEvent &enter_event,
    const ParameterList &parameter_list,
    const ParameterListIndex &param_list_index, IBufferStorage &buffer_storage,
    OptionalPidList excluded_processes) {

  // Create the function
  auto function_param_type =
      module.getTypeByName(kEnterFunctionParameterTypeName);

  if (function_param_type == nullptr) {
    return StringError::create("The " + kEnterFunctionParameterTypeName +
                               " type is not defined");
  }

  auto function_type =
      llvm::FunctionType::get(llvmTypeForMemoryPointer(module),
                              {function_param_type->getPointerTo()}, false);

  auto function_ptr =
      llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
                             kEnterFunctionName, module);

  if (function_ptr == nullptr) {
    return StringError::create("Failed to create the exit function");
  }

  function_ptr->setSection(kEnterFunctionName + "_section");
  function_ptr->arg_begin()->setName("args");

  // Generate the entry basic block
  auto &context = module.getContext();
  llvm::IRBuilder<> builder(context);

  auto entry_bb = llvm::BasicBlock::Create(context, "entry", function_ptr);
  builder.SetInsertPoint(entry_bb);

  // Create the syscall interface helper
  auto bpf_syscall_interface_exp = ebpf::BPFSyscallInterface::create(builder);
  if (!bpf_syscall_interface_exp.succeeded()) {
    return bpf_syscall_interface_exp.error();
  }

  auto bpf_syscall_interface = bpf_syscall_interface_exp.takeValue();

  // Allocate the required stack space
  StackAllocationList stack_allocation_list;

  if (enter_event.type() == ebpf::IPerfEvent::Type::Kprobe) {
    auto args_type = module.getTypeByName(kEnterFunctionParameterTypeName);

    auto success_exp = allocateStackSpace(stack_allocation_list, "pt_regs",
                                          builder, args_type);

    if (success_exp.failed()) {
      return success_exp.error();
    }
  }

  auto success_exp =
      allocateStackSpace(stack_allocation_list, "generic_map_index_32", builder,
                         builder.getInt32Ty());

  if (success_exp.failed()) {
    return success_exp.error();
  }

  success_exp =
      allocateStackSpace(stack_allocation_list, "generic_map_index_64", builder,
                         builder.getInt64Ty());

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Exclude our own process id and anything else specified inside
  // the excluded_processes parameter
  PidList excluded_pid_list;
  if (excluded_processes.has_value()) {
    excluded_pid_list = excluded_processes.value();
  }

  excluded_pid_list.insert(getpid());

  auto process_id = bpf_syscall_interface->getCurrentPidTgid();

  process_id = builder.CreateBinOp(llvm::Instruction::LShr, process_id,
                                   builder.getInt64(32U));

  for (auto pid : excluded_pid_list) {
    auto process_id_cond = builder.CreateICmpEQ(
        process_id, builder.getInt64(static_cast<std::uint64_t>(pid)));

    auto discard_event_bb =
        llvm::BasicBlock::Create(context, "discard_event", function_ptr);

    auto process_event_bb =
        llvm::BasicBlock::Create(context, "process_event", function_ptr);

    builder.CreateCondBr(process_id_cond, discard_event_bb, process_event_bb);

    builder.SetInsertPoint(discard_event_bb);
    builder.CreateRet(builder.getInt64(0));

    builder.SetInsertPoint(process_event_bb);
  }

  // Acquire the event scratch space
  auto event_type = module.getTypeByName(kEventTypeName);
  if (event_type == nullptr) {
    return StringError::create("The " + kEventTypeName +
                               " type is not defined");
  }

  auto scratch_space_exp = getMapEntry(
      event_scratch_space.fd(), builder, *bpf_syscall_interface.get(),
      stack_allocation_list, builder.getInt32(0), event_type->getPointerTo(),
      "event_scratch_space");

  if (!scratch_space_exp.succeeded()) {
    return scratch_space_exp.error();
  }

  auto scratch_space = scratch_space_exp.takeValue();

  // Generate the event header
  success_exp = generateEventHeader(
      builder, enter_event, *bpf_syscall_interface.get(), scratch_space);

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Acquire the buffer storage index generator
  auto buffer_storage_index_generator_exp = getMapEntry(
      buffer_storage.indexMap(), builder, *bpf_syscall_interface.get(),
      stack_allocation_list, builder.getInt32(0),
      builder.getInt32Ty()->getPointerTo(), "buffer_storage_index_generator");

  if (!buffer_storage_index_generator_exp.succeeded()) {
    return buffer_storage_index_generator_exp.error();
  }

  auto buffer_storage_index_generator =
      buffer_storage_index_generator_exp.takeValue();

  VariableList variable_list;
  success_exp = saveVariable(variable_list, "buffer_storage_index_generator",
                             buffer_storage_index_generator);

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Generate the event data
  success_exp = generateEnterEventData(
      builder, enter_event, *bpf_syscall_interface.get(), scratch_space,
      parameter_list, param_list_index, buffer_storage, stack_allocation_list,
      variable_list);

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Generate a key for the event map
  auto event_key_value = bpf_syscall_interface->getCurrentPidTgid();

  auto event_key_exp =
      getStackAllocation(stack_allocation_list, "generic_map_index_64");

  if (!event_key_exp.succeeded()) {
    return event_key_exp.error();
  }

  auto event_key = event_key_exp.takeValue();
  builder.CreateStore(event_key_value, event_key);

  // Save the event object inside the event map
  bpf_syscall_interface->mapUpdateElem(event_map.fd(), scratch_space, event_key,
                                       BPF_ANY);

  builder.CreateRet(builder.getInt64(0));
  return {};
}

SuccessOrStringError FunctionTracer::generateEventHeader(
    llvm::IRBuilder<> &builder, ebpf::IPerfEvent &enter_event,
    ebpf::BPFSyscallInterface &bpf_syscall_interface,
    llvm::Value *event_object) {

  auto current_bb = builder.GetInsertBlock();
  auto &module = *current_bb->getModule();

  // Get the event header from the event object
  auto event_header = builder.CreateGEP(
      event_object, {builder.getInt32(0), builder.getInt32(0)});

  // Event object size, including the size field itself
  auto event_type = module.getTypeByName(kEventTypeName);
  if (event_type == nullptr) {
    return StringError::create("The type " + kEventTypeName +
                               " is not defined");
  }

  auto event_object_size = static_cast<std::uint32_t>(
      ebpf::getLLVMStructureSize(event_type, &module));

  auto event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(0U)});

  builder.CreateStore(builder.getInt32(event_object_size), event_header_field);

  // Event identifier
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(1U)});

  auto event_identifier = static_cast<std::uint64_t>(enter_event.fd());
  builder.CreateStore(builder.getInt64(event_identifier), event_header_field);

  // Timestamp
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(2U)});

  auto timestamp = bpf_syscall_interface.ktimeGetNs();
  builder.CreateStore(timestamp, event_header_field);

  // pid, tgid
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(3U)});

  auto pid_tgid = bpf_syscall_interface.getCurrentPidTgid();
  builder.CreateStore(pid_tgid, event_header_field);

  // uid, gid
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(4U)});

  auto uid_gid = bpf_syscall_interface.getCurrentUidGid();
  builder.CreateStore(uid_gid, event_header_field);

  // cgroup id
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(5U)});

  auto cgroup_id = bpf_syscall_interface.getCurrentCgroupId();
  builder.CreateStore(cgroup_id, event_header_field);

  // Exit code (initialize to zero)
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(6U)});

  builder.CreateStore(builder.getInt64(0U), event_header_field);

  // Probe error flag (initialize to zero)
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(7U)});

  builder.CreateStore(builder.getInt64(0U), event_header_field);

  // Call duration (initialize to zero)
  event_header_field = builder.CreateGEP(
      event_header, {builder.getInt32(0U), builder.getInt32(8U)});

  builder.CreateStore(builder.getInt64(0U), event_header_field);

  return {};
}

SuccessOrStringError FunctionTracer::generateEnterEventData(
    llvm::IRBuilder<> &builder, ebpf::IPerfEvent &enter_event,
    ebpf::BPFSyscallInterface &bpf_syscall_interface, llvm::Value *event_object,
    const ParameterList &valid_param_list,
    const ParameterListIndex &param_list_index, IBufferStorage &buffer_storage,
    const StackAllocationList &allocation_list,
    const VariableList &variable_list) {

  if (valid_param_list.empty()) {
    return {};
  }

  // Get the event data from the event object
  auto event_data = builder.CreateGEP(
      event_object, {builder.getInt32(0), builder.getInt32(1)});

  // Get the args parameter from the function
  auto current_bb = builder.GetInsertBlock();
  auto current_function = current_bb->getParent();

  llvm::Value *args_data = current_function->arg_begin();

  if (enter_event.type() == ebpf::IPerfEvent::Type::Kprobe) {
    // The real pt_regs is pointed to by the first argument
    auto first_arg_index_exp = translateParameterNumberToPtregsIndex(0);
    if (!first_arg_index_exp.succeeded()) {
      return first_arg_index_exp.error();
    }

    auto first_arg_index =
        static_cast<std::uint32_t>(first_arg_index_exp.takeValue());

    auto real_pt_regs_ptr_ref = builder.CreateGEP(
        args_data, {builder.getInt32(0), builder.getInt32(first_arg_index)});

    auto real_pt_regs_ptr = builder.CreateLoad(real_pt_regs_ptr_ref);

    // Get the space we have allocated for the new ptr_regs
    auto new_pt_regs_exp = getStackAllocation(allocation_list, "pt_regs");
    if (!new_pt_regs_exp.succeeded()) {
      return new_pt_regs_exp.error();
    }

    args_data = new_pt_regs_exp.takeValue();

    // Determine how many fields we have to copy
    auto module = current_bb->getModule();
    llvm::DataLayout data_layout(module);

    auto pt_regs_type = args_data->getType()->getPointerElementType();

    auto pt_regs_size =
        static_cast<std::uint32_t>(data_layout.getTypeAllocSize(pt_regs_type));

    auto field_count = pt_regs_size / 8U;

    for (std::uint32_t field_index = 0U; field_index < field_count;
         ++field_index) {
      auto destination_ptr = builder.CreateGEP(
          args_data, {builder.getInt32(0), builder.getInt32(field_index)});

      auto source_ptr =
          builder.CreateBinOp(llvm::Instruction::Add, real_pt_regs_ptr,
                              builder.getInt64(field_index * 8));

      bpf_syscall_interface.probeRead(destination_ptr, builder.getInt32(8),
                                      source_ptr);
    }
  }

  // Go through each parameter and copy it (by value) to the event data
  // structure
  for (const auto &param_index_entry : param_list_index) {
    // Get the source field from the args structure
    auto args_index =
        static_cast<std::uint32_t>(param_index_entry.source_index);

    // Kprobes/Uprobes use a thread context structure to pass the BPF program
    // arguments, so we can't simply access things in order like we do with
    // tracepoints.
    //
    // We have to map the parameter index (1 to 6) to the right register
    // according to the ABI, and then get the right field from the pt_regs
    // structure
    if (enter_event.type() == ebpf::IPerfEvent::Type::Kprobe ||
        enter_event.type() == ebpf::IPerfEvent::Type::Uprobe) {

      auto args_index_exp = translateParameterNumberToPtregsIndex(args_index);

      if (!args_index_exp.succeeded()) {
        return args_index_exp.error();
      }

      args_index = args_index_exp.takeValue();
    }

    auto args_field = builder.CreateGEP(
        args_data, {builder.getInt32(0), builder.getInt32(args_index)});

    auto args_field_value = builder.CreateLoad(args_field);

    // Store the value
    if (param_index_entry.destination_index_in_opt.has_value()) {
      auto event_data_index = static_cast<std::uint32_t>(
          param_index_entry.destination_index_in_opt.value());

      auto event_data_field =
          builder.CreateGEP(event_data, {builder.getInt32(0),
                                         builder.getInt32(event_data_index)});

      builder.CreateStore(args_field_value, event_data_field);
    }

    if (param_index_entry.destination_index_out_opt.has_value()) {
      auto event_data_index = static_cast<std::uint32_t>(
          param_index_entry.destination_index_out_opt.value());

      auto event_data_field =
          builder.CreateGEP(event_data, {builder.getInt32(0),
                                         builder.getInt32(event_data_index)});

      builder.CreateStore(args_field_value, event_data_field);
    }
  }

  // Capture the IN parameters
  std::unordered_map<std::string, llvm::Value *> integer_parameter_map;

  auto event_header = builder.CreateGEP(
      event_object, {builder.getInt32(0), builder.getInt32(0)});

  auto probe_error_flag = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(7)});

  for (const auto &param_index_entry : param_list_index) {
    if (!param_index_entry.destination_index_in_opt.has_value()) {
      continue;
    }

    const auto &param = valid_param_list.at(param_index_entry.param_index);

    auto event_data_index = static_cast<std::uint32_t>(
        param_index_entry.destination_index_in_opt.value());

    auto event_data_field = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(event_data_index)});

    if (param.type == Parameter::Type::Integer) {
      integer_parameter_map.insert({"in:" + param.name, event_data_field});

    } else if (param.type == Parameter::Type::IntegerPtr) {
      captureIntegerByPointer(builder, bpf_syscall_interface, param,
                              event_data_field, probe_error_flag);

      integer_parameter_map.insert({"in:" + param.name, event_data_field});

    } else if (param.type == Parameter::Type::Buffer) {
      if (!param.opt_size_var.has_value()) {
        return StringError::create("Missing size field for Buffer parameter");
      }

      const auto &size_var = param.opt_size_var.value();
      llvm::Value *buffer_size = nullptr;

      if (std::holds_alternative<std::size_t>(size_var)) {
        auto size = std::get<std::size_t>(size_var);
        buffer_size = builder.getInt32(static_cast<std::uint32_t>(size));

      } else if (std::holds_alternative<std::string>(size_var)) {
        const auto &size_var_name = std::get<std::string>(size_var);

        auto size_ref_it = integer_parameter_map.find("in:" + size_var_name);
        if (size_ref_it == integer_parameter_map.end()) {
          return StringError::create(
              "Invalid size reference for Buffer parameter named " +
              param.name);
        }

        const auto &size_integer_ptr = size_ref_it->second;

        // Integers from the event data structure are always 64-bit. When
        // capturing buffers we always use 32-bit size values
        buffer_size = builder.CreateLoad(size_integer_ptr);

        buffer_size =
            builder.CreateIntCast(buffer_size, builder.getInt32Ty(), false);

        buffer_size = builder.CreateBinOp(llvm::Instruction::And, buffer_size,
                                          builder.getInt32(0x7FFFFFFF));

      } else {
        return StringError::create(
            "Invalid size field type for Buffer parameter");
      }

      auto success_exp =
          captureBuffer(builder, bpf_syscall_interface, buffer_storage,
                        allocation_list, variable_list, event_data_field,
                        param.name, probe_error_flag, buffer_size);

      if (success_exp.failed()) {
        return success_exp.error();
      }

    } else if (param.type == Parameter::Type::String) {
      auto success_exp = captureString(
          builder, bpf_syscall_interface, buffer_storage, allocation_list,
          variable_list, event_data_field, param.name, probe_error_flag);

      if (success_exp.failed()) {
        return success_exp.error();
      }

    } else if (param.type == Parameter::Type::Argv) {
      const auto &size_var = param.opt_size_var.value();
      auto argv_size = std::get<std::size_t>(size_var);

      auto success_exp =
          captureArgv(builder, bpf_syscall_interface, buffer_storage,
                      allocation_list, variable_list, event_data_field,
                      param.name, probe_error_flag, argv_size);

      if (success_exp.failed()) {
        return success_exp.error();
      }

    } else {
      return StringError::create("Invalid parameter type encountered");
    }
  }

  return {};
}

SuccessOrStringError FunctionTracer::createExitFunction(
    llvm::Module &module, EventMap &event_map, ebpf::IPerfEvent &exit_event,
    const ParameterList &parameter_list,
    const ParameterListIndex &param_list_index, IBufferStorage &buffer_storage,
    ebpf::PerfEventArray &perf_event_array, bool skip_exit_code) {

  // Create the function
  auto function_param_type =
      module.getTypeByName(kExitFunctionParameterTypeName);

  if (function_param_type == nullptr) {
    return StringError::create("The " + kExitFunctionParameterTypeName +
                               " type is not defined");
  }

  auto function_type =
      llvm::FunctionType::get(llvmTypeForMemoryPointer(module),
                              {function_param_type->getPointerTo()}, false);

  auto function_ptr =
      llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
                             kExitFunctionName, module);

  if (function_ptr == nullptr) {
    return StringError::create("Failed to create the exit function");
  }

  function_ptr->setSection(kExitFunctionName + "_section");

  auto exit_function_args = function_ptr->arg_begin();
  exit_function_args->setName("args");

  // Generate the entry basic block
  auto &context = module.getContext();
  llvm::IRBuilder<> builder(context);

  auto entry_bb = llvm::BasicBlock::Create(context, "entry", function_ptr);
  builder.SetInsertPoint(entry_bb);

  // Allocate the required stack space
  StackAllocationList stack_allocation_list;

  auto success_exp =
      allocateStackSpace(stack_allocation_list, "generic_map_index_32", builder,
                         builder.getInt32Ty());

  if (success_exp.failed()) {
    return success_exp.error();
  }

  success_exp =
      allocateStackSpace(stack_allocation_list, "generic_map_index_64", builder,
                         builder.getInt64Ty());

  if (success_exp.failed()) {
    return success_exp.error();
  }

  success_exp = allocateStackSpace(stack_allocation_list, "event_key", builder,
                                   builder.getInt64Ty());

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Generate a key for the event map
  auto bpf_syscall_interface_exp = ebpf::BPFSyscallInterface::create(builder);
  if (!bpf_syscall_interface_exp.succeeded()) {
    return bpf_syscall_interface_exp.error();
  }

  auto bpf_syscall_interface = bpf_syscall_interface_exp.takeValue();
  auto event_key_value = bpf_syscall_interface->getCurrentPidTgid();

  auto event_key_exp = getStackAllocation(stack_allocation_list, "event_key");

  if (!event_key_exp.succeeded()) {
    return event_key_exp.error();
  }

  auto event_key = event_key_exp.takeValue();
  builder.CreateStore(event_key_value, event_key);

  // Acquire the event object stored by the entry program
  auto event_type = module.getTypeByName(kEventTypeName);
  if (event_type == nullptr) {
    return StringError::create("The " + kEventTypeName +
                               " type is not defined");
  }

  auto event_entry_exp =
      getMapEntry(event_map.fd(), builder, *bpf_syscall_interface.get(),
                  stack_allocation_list, event_key_value,
                  event_type->getPointerTo(), "event_entry");

  if (!event_entry_exp.succeeded()) {
    return event_entry_exp.error();
  }

  auto event_entry = event_entry_exp.takeValue();

  // Get the event header from the event object
  auto event_header = builder.CreateGEP(
      event_entry, {builder.getInt32(0), builder.getInt32(0)});

  // Update the exit code in the event header
  if (!skip_exit_code) {
    auto event_header_exit_code = builder.CreateGEP(
        event_header, {builder.getInt32(0), builder.getInt32(6)});

    llvm::Value *function_exit_code_value{nullptr};

    if (exit_event.type() == ebpf::IPerfEvent::Type::Tracepoint) {
      // Skip the tracepoint header and get the 'ret' parameter
      auto function_exit_code = builder.CreateGEP(
          exit_function_args, {builder.getInt32(0), builder.getInt32(5)});

      function_exit_code_value = builder.CreateLoad(function_exit_code);

    } else {
      auto function_exit_code_value_exp =
          getReturnValuePtregsEntry(builder, exit_function_args);

      if (!function_exit_code_value_exp.succeeded()) {
        return function_exit_code_value_exp.error();
      }

      auto function_exit_code_index = function_exit_code_value_exp.takeValue();
      function_exit_code_value = builder.CreateLoad(function_exit_code_index);
    }

    builder.CreateStore(function_exit_code_value, event_header_exit_code);

    // If we are required to also re-capture the exit code with the special
    // EXIT_CODE parameter, then copy this value inside the EventData struct.
    // The capture logic will take from here and do the rest of the work for us.
    auto exit_code_it = std::find_if(
        param_list_index.begin(), param_list_index.end(),

        [&parameter_list](
            const FunctionTracer::ParameterListIndexEntry &index_entry)
            -> bool {
          const auto &param = parameter_list.at(index_entry.param_index);
          return param.name == kSpecialExitCodeParameterName;
        });

    if (exit_code_it != param_list_index.end()) {
      const auto &exit_code_entry = *exit_code_it;

      if (!exit_code_entry.destination_index_out_opt.has_value()) {
        return StringError::create("");
      }

      auto exit_dest_index = static_cast<std::uint32_t>(
          exit_code_entry.destination_index_out_opt.value());

      auto event_data = builder.CreateGEP(
          event_entry, {builder.getInt32(0), builder.getInt32(1)});

      auto exit_event_data_field = builder.CreateGEP(
          event_data, {builder.getInt32(0), builder.getInt32(exit_dest_index)});

      builder.CreateStore(function_exit_code_value, exit_event_data_field);
    }
  }

  // Set the call duration in the event header
  auto enter_time_ptr = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(2)});

  auto enter_time = builder.CreateLoad(enter_time_ptr);
  auto exit_time = bpf_syscall_interface->ktimeGetNs();

  auto call_duration =
      builder.CreateBinOp(llvm::Instruction::Sub, exit_time, enter_time);

  auto call_duration_ptr = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(8)});

  builder.CreateStore(call_duration, call_duration_ptr);

  // Acquire the buffer storage index generator
  auto buffer_storage_index_generator_exp = getMapEntry(
      buffer_storage.indexMap(), builder, *bpf_syscall_interface.get(),
      stack_allocation_list, builder.getInt32(0),
      builder.getInt32Ty()->getPointerTo(), "buffer_storage_index_generator");

  if (!buffer_storage_index_generator_exp.succeeded()) {
    return buffer_storage_index_generator_exp.error();
  }

  auto buffer_storage_index_generator =
      buffer_storage_index_generator_exp.takeValue();

  VariableList variable_list;
  success_exp = saveVariable(variable_list, "buffer_storage_index_generator",
                             buffer_storage_index_generator);

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Generate the event data
  success_exp = generateExitEventData(
      builder, *bpf_syscall_interface.get(), event_entry, parameter_list,
      param_list_index, buffer_storage, stack_allocation_list, variable_list);

  if (success_exp.failed()) {
    return success_exp.error();
  }

  // Send the data through perf_event
  auto perf_event_fd = perf_event_array.fd();

  auto event_entry_size = static_cast<std::uint32_t>(
      ebpf::getLLVMStructureSize(event_type, &module));

  bpf_syscall_interface->perfEventOutput(exit_function_args, perf_event_fd,
                                         event_entry, event_entry_size);

  // Delete the event from the map
  bpf_syscall_interface->mapDeleteElem(event_map.fd(), event_key);

  builder.CreateRet(builder.getInt64(0));
  return {};
}

SuccessOrStringError FunctionTracer::generateExitEventData(
    llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface, llvm::Value *event_object,
    const ParameterList &valid_param_list,
    const ParameterListIndex &param_list_index, IBufferStorage &buffer_storage,
    const StackAllocationList &allocation_list,
    const VariableList &variable_list) {

  if (valid_param_list.empty()) {
    return {};
  }

  // Get the event data from the event object
  auto event_data = builder.CreateGEP(
      event_object, {builder.getInt32(0), builder.getInt32(1)});

  // Get the event header from the event object
  auto event_header = builder.CreateGEP(
      event_object, {builder.getInt32(0), builder.getInt32(0)});

  auto probe_error_flag = builder.CreateGEP(
      event_header, {builder.getInt32(0), builder.getInt32(7)});

  // Map all the integer fields
  std::unordered_map<std::string, llvm::Value *> integer_parameter_map;

  for (const auto &param_index_entry : param_list_index) {
    const auto &param = valid_param_list.at(param_index_entry.param_index);

    if (param.type == Parameter::Type::Integer ||
        param.type == Parameter::Type::IntegerPtr) {

      if (param_index_entry.destination_index_in_opt.has_value()) {
        auto event_data_index = static_cast<std::uint32_t>(
            param_index_entry.destination_index_in_opt.value());

        auto event_data_field =
            builder.CreateGEP(event_data, {builder.getInt32(0),
                                           builder.getInt32(event_data_index)});

        integer_parameter_map.insert({"in:" + param.name, event_data_field});
      }

      if (param_index_entry.destination_index_out_opt.has_value()) {

        auto event_data_index = static_cast<std::uint32_t>(
            param_index_entry.destination_index_out_opt.value());

        auto event_data_field =
            builder.CreateGEP(event_data, {builder.getInt32(0),
                                           builder.getInt32(event_data_index)});

        integer_parameter_map.insert({"out:" + param.name, event_data_field});
      }
    }
  }

  // Capture the OUT parameters
  for (const auto &param_index_entry : param_list_index) {
    const auto &param = valid_param_list.at(param_index_entry.param_index);

    if (!param_index_entry.destination_index_out_opt.has_value()) {
      continue;
    }

    auto event_data_index = static_cast<std::uint32_t>(
        param_index_entry.destination_index_out_opt.value());

    auto event_data_field = builder.CreateGEP(
        event_data, {builder.getInt32(0), builder.getInt32(event_data_index)});

    if (param.type == Parameter::Type::IntegerPtr) {
      captureIntegerByPointer(builder, bpf_syscall_interface, param,
                              event_data_field, probe_error_flag);

    } else if (param.type == Parameter::Type::Buffer) {
      if (!param.opt_size_var.has_value()) {
        return StringError::create("Missing size field for Buffer parameter");
      }

      const auto &size_var = param.opt_size_var.value();
      llvm::Value *buffer_size = nullptr;

      if (std::holds_alternative<std::size_t>(size_var)) {
        auto size = std::get<std::size_t>(size_var);
        buffer_size = builder.getInt32(static_cast<std::uint32_t>(size));

      } else if (std::holds_alternative<std::string>(size_var)) {
        const auto &size_var_name = std::get<std::string>(size_var);

        auto size_ref_it = integer_parameter_map.find("out:" + size_var_name);
        if (size_ref_it == integer_parameter_map.end()) {
          return StringError::create(
              "Invalid size reference for Buffer parameter named " +
              param.name);
        }

        const auto &size_integer_ptr = size_ref_it->second;

        // Integers from the event data structure are always 64-bit. When
        // capturing buffers we always use 32-bit size values
        buffer_size = builder.CreateLoad(size_integer_ptr);

        buffer_size =
            builder.CreateIntCast(buffer_size, builder.getInt32Ty(), false);

        buffer_size = builder.CreateBinOp(llvm::Instruction::And, buffer_size,
                                          builder.getInt32(0x7FFFFFFF));

      } else {
        return StringError::create(
            "Invalid size field type for Buffer parameter");
      }

      auto success_exp =
          captureBuffer(builder, bpf_syscall_interface, buffer_storage,
                        allocation_list, variable_list, event_data_field,
                        param.name, probe_error_flag, buffer_size);

      if (success_exp.failed()) {
        return success_exp.error();
      }

    } else if (param.type == Parameter::Type::String) {
      auto success_exp = captureString(
          builder, bpf_syscall_interface, buffer_storage, allocation_list,
          variable_list, event_data_field, param.name, probe_error_flag);

      if (success_exp.failed()) {
        return success_exp.error();
      }

    } else {
      return StringError::create("Invalid parameter type encountered");
    }
  }

  return {};
}

void FunctionTracer::captureIntegerByPointer(
    llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface, const Parameter &param,
    llvm::Value *event_data_field, llvm::Value *probe_error_flag) {

  auto current_bb = builder.GetInsertBlock();
  auto &context = current_bb->getContext();
  auto current_function = current_bb->getParent();

  // Read the integer address first
  auto buffer_address = builder.CreateLoad(event_data_field);

  // Skip the read if the pointer is set to nullptr
  auto buffer_address_cond =
      builder.CreateICmpEQ(builder.getInt64(0U), buffer_address);

  auto skip_integer_read_bb = llvm::BasicBlock::Create(
      context, "skip_" + param.name + "_ptr_read", current_function);

  auto read_integer_bb = llvm::BasicBlock::Create(
      context, "read_" + param.name + "_integer_ptr", current_function);

  builder.CreateCondBr(buffer_address_cond, skip_integer_read_bb,
                       read_integer_bb);

  builder.SetInsertPoint(read_integer_bb);

  // The Parameter structure has already been validated; take the integer size
  auto integer_size = std::get<std::size_t>(param.opt_size_var.value());

  // Read the integer and update the probe error flag in the event header
  // The reader will have to extract the value from the 8-bytes buffer
  auto integer_size_value =
      builder.getInt32(static_cast<std::uint32_t>(integer_size));

  auto read_error = bpf_syscall_interface.probeRead(
      event_data_field, integer_size_value, buffer_address);

  read_error = builder.CreateBinOp(llvm::Instruction::And, read_error,
                                   builder.getInt64(0x8000000000000000ULL));

  read_error = builder.CreateBinOp(
      llvm::Instruction::Or, builder.CreateLoad(probe_error_flag), read_error);

  builder.CreateStore(read_error, probe_error_flag);

  builder.CreateBr(skip_integer_read_bb);
  builder.SetInsertPoint(skip_integer_read_bb);
}

StringErrorOr<FunctionTracer::EventList> FunctionTracer::parseEventData(
    BufferReader &buffer_reader, std::uint32_t event_object_size,
    std::uint64_t event_object_identifier, const std::string &event_name,
    const ParameterList &parameter_list,
    const ParameterListIndex &param_list_index,
    IBufferStorage &buffer_storage) {

  EventList output;
  bool first_event_object{true};

  for (;;) {
    // If this is the first iteration, the event size/identifier must match
    // what we need, since the PerfEventReader expects us to always parse
    // at least one event

    if (buffer_reader.availableBytes() == 0U) {
      if (first_event_object) {
        return StringError::create("Empty event buffer received");
      }

      break;
    }

    auto event_size = buffer_reader.peekU32(0U);
    if (event_size != event_object_size) {
      if (first_event_object) {
        return StringError::create("Invalid event object size");
      }

      break;
    }

    auto event_id = buffer_reader.peekU64(4U);
    if (event_id != event_object_identifier) {
      if (first_event_object) {
        return StringError::create("Invalid event object identifier");
      }

      break;
    }

    if (buffer_reader.availableBytes() < event_object_size) {
      return StringError::create(
          "Not enough bytes to acquire a full event object");
    }

    buffer_reader.skipBytes(12U);
    first_event_object = false;

    // Get the event header
    Event event = {};
    event.identifier = event_object_identifier;
    event.name = event_name;
    event.header.timestamp = buffer_reader.u64();

    auto pid_tgid = buffer_reader.u64();
    event.header.thread_id = static_cast<pid_t>(pid_tgid & 0xFFFFFFFFULL);
    event.header.process_id =
        static_cast<pid_t>((pid_tgid & 0xFFFFFFFF00000000ULL) >> 32U);

    auto uid_gid = buffer_reader.u64();
    event.header.user_id = static_cast<uid_t>(uid_gid & 0xFFFFFFFFULL);
    event.header.group_id =
        static_cast<gid_t>((uid_gid & 0xFFFFFFFF00000000ULL) >> 32U);

    event.header.cgroup_id = buffer_reader.u64();
    event.header.exit_code = buffer_reader.u64();
    event.header.probe_error = (buffer_reader.u64() != 0);
    event.header.duration = buffer_reader.u64();

    // Get the event data
    std::unordered_map<std::string, std::uint64_t> integer_parameter_map;
    std::size_t highest_offset_read = 0U;

    for (const auto &index_entry : param_list_index) {
      const auto &param = parameter_list.at(index_entry.param_index);

      // Get the field data from the right offsets; we can get either one
      // or both the IN and OUT values
      std::vector<std::optional<std::uint64_t>> opt_field_value_list;

      if (index_entry.destination_index_in_opt.has_value()) {
        auto offset = index_entry.destination_index_in_opt.value() * 8U;
        highest_offset_read = std::max(offset, highest_offset_read);

        auto value = buffer_reader.peekU64(offset);
        opt_field_value_list.push_back(value);
      } else {
        opt_field_value_list.push_back({});
      }

      if (index_entry.destination_index_out_opt.has_value()) {
        auto offset = index_entry.destination_index_out_opt.value() * 8U;
        highest_offset_read = std::max(offset, highest_offset_read);

        auto value = buffer_reader.peekU64(offset);
        opt_field_value_list.push_back(value);
      } else {
        opt_field_value_list.push_back({});
      }

      // Process the IN and OUT values we captured
      for (auto opt_field_value_it = opt_field_value_list.begin();
           opt_field_value_it != opt_field_value_list.end();
           ++opt_field_value_it) {

        bool in_parameter = opt_field_value_it == opt_field_value_list.begin();
        std::string name_prefix = in_parameter ? "in:" : "out:";

        const auto &opt_field_value = *opt_field_value_it;
        if (!opt_field_value.has_value()) {
          continue;
        }

        Event::Field event_field = {};
        event_field.in = in_parameter;
        event_field.name = param.name;

        auto value = opt_field_value.value();

        if (param.type == Parameter::Type::Integer ||
            param.type == Parameter::Type::IntegerPtr) {

          if (param.type == Parameter::Type::IntegerPtr) {
            auto integer_size =
                std::get<std::size_t>(param.opt_size_var.value());

            switch (integer_size) {
            case 1U:
              value &= 0xFFULL;
              break;

            case 2U:
              value &= 0xFFFFULL;
              break;

            case 4U:
              value &= 0xFFFFFFFFULL;
              break;

            case 8U:
              break;
            }
          }

          event_field.data_var = value;
          integer_parameter_map.insert({name_prefix + param.name, value});

        } else if (param.type == Parameter::Type::String) {
          Event::Field::Buffer buffer;
          auto map_error = buffer_storage.getBuffer(buffer, value);
          if (map_error.succeeded()) {
            auto string_value = stringFromBufferData(buffer);
            event_field.data_var = std::move(string_value);

          } else {
            event_field.data_var = std::to_string(value);
          }

        } else if (param.type == Parameter::Type::Buffer) {
          Event::Field::Buffer buffer;
          auto map_error = buffer_storage.getBuffer(buffer, value);
          if (map_error.succeeded()) {
            if (!param.opt_size_var.has_value()) {
              return StringError::create("Buffer parameter named " +
                                         param.name +
                                         " does not have a valid size value");
            }

            const auto &size_var = param.opt_size_var.value();

            std::size_t buffer_size = 0U;
            if (std::holds_alternative<std::size_t>(size_var)) {
              buffer_size = std::get<std::size_t>(size_var);

            } else if (std::holds_alternative<std::string>(size_var)) {
              const auto &size_var_name = std::get<std::string>(size_var);
              auto integer_name = name_prefix + size_var_name;

              auto integer_it = integer_parameter_map.find(integer_name);
              if (integer_it == integer_parameter_map.end()) {
                return StringError::create(
                    "Buffer parameter named " + param.name +
                    " uses an invalid size reference: " + integer_name);
              }

              buffer_size = static_cast<std::size_t>(integer_it->second);
            }

            buffer_size = std::min(buffer_size, buffer.size());
            buffer.resize(buffer_size);

            event_field.data_var = std::move(buffer);

          } else {
            event.header.probe_error = true;
            event_field.data_var = Event::Field::Buffer();
          }

        } else if (param.type == Parameter::Type::Argv) {
          Event::Field::Argv argv_data;

          Event::Field::Buffer buffer;
          auto map_error = buffer_storage.getBuffer(buffer, value);
          if (map_error.succeeded()) {
            const auto &size_var = param.opt_size_var.value();
            auto argv_size = std::get<std::size_t>(size_var);

            bool terminator_found{false};

            for (auto argv_index = 0U; argv_index < argv_size; ++argv_index) {
              auto offset = buffer.data() + (argv_index * 8U);

              std::uint64_t buffer_index{0U};
              std::memcpy(&buffer_index, offset, sizeof(buffer_index));

              if (buffer_index == 0) {
                terminator_found = true;
                break;
              }

              Event::Field::Buffer argv_entry;
              map_error = buffer_storage.getBuffer(argv_entry, buffer_index);
              if (map_error.succeeded()) {
                auto string_value = stringFromBufferData(argv_entry);
                argv_data.push_back(string_value);

              } else {
                event.header.probe_error = true;
                event_field.data_var = Event::Field::Argv();
              }
            }

            if (!terminator_found) {
              event.header.probe_error = true;
            }

            event_field.data_var = argv_data;

          } else {
            event.header.probe_error = true;
            event_field.data_var = Event::Field::Argv();
          }

        } else {
          return StringError::create("Invalid parameter type");
        }

        IFunctionTracer::Event::FieldMap *field_map = nullptr;
        if (event_field.in) {
          field_map = &event.in_field_map;
        } else {
          field_map = &event.out_field_map;
        }

        field_map->insert({event_field.name, std::move(event_field)});
      }
    }

    buffer_reader.skipBytes(highest_offset_read + 8U);
    output.push_back(std::move(event));
  }

  return output;
}

SuccessOrStringError FunctionTracer::captureString(
    llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface,
    IBufferStorage &buffer_storage, const StackAllocationList &allocation_list,
    const VariableList &variable_list, llvm::Value *event_data_field,
    const std::string &parameter_name, llvm::Value *probe_error_flag) {

  auto string_address = builder.CreateLoad(event_data_field);

  // Skip the read if the pointer is set to nullptr
  auto current_bb = builder.GetInsertBlock();
  auto &context = current_bb->getContext();
  auto current_function = current_bb->getParent();

  auto string_address_cond =
      builder.CreateICmpEQ(builder.getInt64(0U), string_address);

  auto skip_string_read_bb = llvm::BasicBlock::Create(
      context, "skip_" + parameter_name + "_string_read", current_function);

  auto read_string_bb = llvm::BasicBlock::Create(
      context, "read_" + parameter_name + "_string", current_function);

  builder.CreateCondBr(string_address_cond, skip_string_read_bb,
                       read_string_bb);

  builder.SetInsertPoint(read_string_bb);

  // Generate a new buffer storage index
  auto buffer_storage_index_exp =
      generateBufferStorageIndex(builder, variable_list, buffer_storage);

  if (!buffer_storage_index_exp.succeeded()) {
    return buffer_storage_index_exp.error();
  }

  auto buffer_storage_index = buffer_storage_index_exp.takeValue();

  // Acquire the buffer storage entry
  auto buffer_storage_entry_exp =
      getMapEntry(buffer_storage.bufferMap(), builder, bpf_syscall_interface,
                  allocation_list, buffer_storage_index, builder.getInt8PtrTy(),
                  parameter_name + "_buffer_storage");

  if (!buffer_storage_entry_exp.succeeded()) {
    return buffer_storage_entry_exp.error();
  }

  auto buffer_storage_entry = buffer_storage_entry_exp.takeValue();

  // Read the string
  auto read_error = bpf_syscall_interface.probeReadStr(
      buffer_storage_entry, buffer_storage.bufferSize(), string_address);

  // Update the probe error flag in the event header
  read_error = builder.CreateBinOp(llvm::Instruction::And, read_error,
                                   builder.getInt64(0x8000000000000000ULL));

  read_error = builder.CreateBinOp(
      llvm::Instruction::Or, builder.CreateLoad(probe_error_flag), read_error);

  builder.CreateStore(read_error, probe_error_flag);

  // Tag the buffer storage index and save it in the event data
  auto tagged_buffer_storage_index = tagBufferStorageIndex(
      bpf_syscall_interface, builder, buffer_storage_index);

  builder.CreateStore(tagged_buffer_storage_index, event_data_field);

  builder.CreateBr(skip_string_read_bb);
  builder.SetInsertPoint(skip_string_read_bb);

  return {};
}

SuccessOrStringError FunctionTracer::captureBuffer(
    llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface,
    IBufferStorage &buffer_storage, const StackAllocationList &allocation_list,
    const VariableList &variable_list, llvm::Value *event_data_field,
    const std::string &parameter_name, llvm::Value *probe_error_flag,
    llvm::Value *buffer_size) {

  auto buffer_address = builder.CreateLoad(event_data_field);

  // Skip the read if the pointer is set to nullptr
  auto current_bb = builder.GetInsertBlock();
  auto &context = current_bb->getContext();
  auto current_function = current_bb->getParent();

  auto buffer_address_cond =
      builder.CreateICmpEQ(builder.getInt64(0U), buffer_address);

  auto skip_buffer_read_bb = llvm::BasicBlock::Create(
      context, "skip_" + parameter_name + "_buffer_read", current_function);

  auto read_buffer_bb = llvm::BasicBlock::Create(
      context, "read_" + parameter_name + "_buffer", current_function);

  builder.CreateCondBr(buffer_address_cond, skip_buffer_read_bb,
                       read_buffer_bb);

  builder.SetInsertPoint(read_buffer_bb);

  // Generate a new buffer storage index
  auto buffer_storage_index_exp =
      generateBufferStorageIndex(builder, variable_list, buffer_storage);

  if (!buffer_storage_index_exp.succeeded()) {
    return buffer_storage_index_exp.error();
  }

  auto buffer_storage_index = buffer_storage_index_exp.takeValue();

  // Acquire the buffer storage entry
  auto buffer_storage_entry_exp =
      getMapEntry(buffer_storage.bufferMap(), builder, bpf_syscall_interface,
                  allocation_list, buffer_storage_index, builder.getInt8PtrTy(),
                  parameter_name + "_buffer_storage");

  if (!buffer_storage_entry_exp.succeeded()) {
    return buffer_storage_entry_exp.error();
  }

  auto buffer_storage_entry = buffer_storage_entry_exp.takeValue();

  // Make sure the buffer size is correct
  auto eval_buffer_size_bb = llvm::BasicBlock::Create(
      context, "eval_" + parameter_name + "_buffer_size", current_function);

  builder.CreateBr(eval_buffer_size_bb);
  builder.SetInsertPoint(eval_buffer_size_bb);

  auto buffer_storage_entry_size =
      static_cast<std::uint32_t>(buffer_storage.bufferSize());

  auto buffer_size_cond = builder.CreateICmpUGT(
      buffer_size, builder.getInt32(buffer_storage_entry_size));

  auto invalid_buffer_size_bb = llvm::BasicBlock::Create(
      context, "invalid_" + parameter_name + "map_entry_buf_size",
      current_function);

  auto capture_buffer_bb = llvm::BasicBlock::Create(
      context, "capture_" + parameter_name + "_buffer", current_function);

  builder.CreateCondBr(buffer_size_cond, invalid_buffer_size_bb,
                       capture_buffer_bb);

  builder.SetInsertPoint(invalid_buffer_size_bb);

  auto max_buffer_size = builder.getInt32(buffer_storage_entry_size);
  builder.CreateBr(capture_buffer_bb);

  builder.SetInsertPoint(capture_buffer_bb);

  auto buffer_size_phi = builder.CreatePHI(builder.getInt32Ty(), 2);
  buffer_size_phi->addIncoming(max_buffer_size, invalid_buffer_size_bb);
  buffer_size_phi->addIncoming(buffer_size, eval_buffer_size_bb);

  // Read the buffer
  auto read_error = bpf_syscall_interface.probeRead(
      buffer_storage_entry, buffer_size_phi, buffer_address);

  // Update the probe error flag in the event header
  read_error = builder.CreateBinOp(llvm::Instruction::And, read_error,
                                   builder.getInt64(0x8000000000000000ULL));

  read_error = builder.CreateBinOp(
      llvm::Instruction::Or, builder.CreateLoad(probe_error_flag), read_error);

  builder.CreateStore(read_error, probe_error_flag);

  // Tag the buffer storage index and save it in the event data
  auto tagged_buffer_storage_index = tagBufferStorageIndex(
      bpf_syscall_interface, builder, buffer_storage_index);

  builder.CreateStore(tagged_buffer_storage_index, event_data_field);

  builder.CreateBr(skip_buffer_read_bb);
  builder.SetInsertPoint(skip_buffer_read_bb);

  return {};
}

SuccessOrStringError FunctionTracer::captureArgv(
    llvm::IRBuilder<> &builder,
    ebpf::BPFSyscallInterface &bpf_syscall_interface,
    IBufferStorage &buffer_storage, const StackAllocationList &allocation_list,
    const VariableList &variable_list, llvm::Value *event_data_field,
    const std::string &parameter_name, llvm::Value *probe_error_flag,
    std::size_t argv_size) {

  // Skip the read if the pointer is set to nullptr
  auto argv_address = builder.CreateLoad(event_data_field);

  auto current_bb = builder.GetInsertBlock();
  auto &context = current_bb->getContext();
  auto current_function = current_bb->getParent();

  auto argv_address_cond =
      builder.CreateICmpEQ(builder.getInt64(0U), argv_address);

  auto skip_argv_read_bb = llvm::BasicBlock::Create(
      context, "skip_" + parameter_name + "_argv_read", current_function);

  auto read_argv_bb = llvm::BasicBlock::Create(
      context, "read_" + parameter_name + "_argv", current_function);

  builder.CreateCondBr(argv_address_cond, skip_argv_read_bb, read_argv_bb);

  builder.SetInsertPoint(read_argv_bb);

  //
  // In order to capture this, we'll reserve a page in the buffer storage
  // to store all the pointers, and then a page for each string
  //

  // Create a new structure type for the pointer buffer
  std::vector<llvm::Type *> array_type_list(argv_size, builder.getInt64Ty());

  auto array_type = llvm::StructType::create(array_type_list,
                                             "ArgvFor_" + parameter_name, true);

  // Get the first buffer storage entry, used to store the pointer list
  auto buffer_storage_index_exp =
      generateBufferStorageIndex(builder, variable_list, buffer_storage);

  if (!buffer_storage_index_exp.succeeded()) {
    return buffer_storage_index_exp.error();
  }

  auto buffer_storage_index = buffer_storage_index_exp.takeValue();

  auto pointer_buffer_exp = getMapEntry(
      buffer_storage.bufferMap(), builder, bpf_syscall_interface,
      allocation_list, buffer_storage_index, array_type->getPointerTo(),
      parameter_name + "_pointer_buffer");

  if (!pointer_buffer_exp.succeeded()) {
    return pointer_buffer_exp.error();
  }

  auto pointer_buffer = pointer_buffer_exp.takeValue();

  // Go through each argv entry
  auto end_argv_capture_bb = llvm::BasicBlock::Create(
      context, parameter_name + "_capture_end", current_function);

  for (auto argv_index = 0U; argv_index < argv_size; ++argv_index) {
    // Get the pointer to the current argv entry
    auto entry_offset =
        static_cast<std::uint64_t>(argv_index * sizeof(std::uint64_t));

    auto argv_entry_ptr = builder.CreateBinOp(
        llvm::Instruction::Add, argv_address, builder.getInt64(entry_offset));

    // Get the pointer to the current pointer buffer entry
    auto pointer_buffer_entry_ptr = builder.CreateGEP(
        pointer_buffer, {builder.getInt32(0), builder.getInt32(argv_index)});

    builder.CreateStore(argv_entry_ptr, pointer_buffer_entry_ptr);

    // Read the pointer value
    auto read_error = bpf_syscall_interface.probeRead(
        pointer_buffer_entry_ptr, builder.getInt64(8U), argv_entry_ptr);

    // Update the probe error flag in the event header
    read_error = builder.CreateBinOp(llvm::Instruction::And, read_error,
                                     builder.getInt64(0x8000000000000000ULL));

    read_error =
        builder.CreateBinOp(llvm::Instruction::Or,
                            builder.CreateLoad(probe_error_flag), read_error);

    builder.CreateStore(read_error, probe_error_flag);

    // Skip this pointer if we failed to capture it
    auto read_error_cond =
        builder.CreateICmpEQ(read_error, builder.getInt64(0));

    auto label = parameter_name + "_argv_" + std::to_string(argv_index);

    auto evaluate_string_ptr_bb = llvm::BasicBlock::Create(
        context, "evaluate_" + label, current_function);

    auto skip_string_capture_bb =
        llvm::BasicBlock::Create(context, "skip_" + label, current_function);

    builder.CreateCondBr(read_error_cond, evaluate_string_ptr_bb,
                         skip_string_capture_bb);

    builder.SetInsertPoint(evaluate_string_ptr_bb);

    // If this is the null pointer, skip to the end
    auto pointer_buffer_entry = builder.CreateLoad(pointer_buffer_entry_ptr);

    auto capture_string_bb =
        llvm::BasicBlock::Create(context, "capture_" + label, current_function);

    auto string_pointer_cond =
        builder.CreateICmpEQ(pointer_buffer_entry, builder.getInt64(0));

    builder.CreateCondBr(string_pointer_cond, end_argv_capture_bb,
                         capture_string_bb);

    builder.SetInsertPoint(capture_string_bb);

    auto success_exp = captureString(
        builder, bpf_syscall_interface, buffer_storage, allocation_list,
        variable_list, pointer_buffer_entry_ptr, label, probe_error_flag);

    if (success_exp.failed()) {
      return success_exp.error();
    }

    builder.CreateBr(skip_string_capture_bb);
    builder.SetInsertPoint(skip_string_capture_bb);
  }

  // Add the ending basic block
  builder.CreateBr(end_argv_capture_bb);
  builder.SetInsertPoint(end_argv_capture_bb);

  // Replace the argv address in the event data structure with the tagged index
  // for the pointer buffer
  auto tagged_pointer_buffer_index = tagBufferStorageIndex(
      bpf_syscall_interface, builder, buffer_storage_index);

  builder.CreateStore(tagged_pointer_buffer_index, event_data_field);

  builder.CreateBr(skip_argv_read_bb);
  builder.SetInsertPoint(skip_argv_read_bb);

  return {};
}
} // namespace tob::ebpfpub
