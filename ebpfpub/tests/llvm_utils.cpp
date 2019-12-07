#include "llvm_utils.h"

#include <vector>

#include <catch2/catch.hpp>

namespace ebpfpub {
SCENARIO("Determining LLVM structure size", "[LLVM Utils]") {
  GIVEN("an LLVM structure type and module") {
    static const std::string kTestStructureName{"TestStructure"};

    llvm::LLVMContext llvm_context;

    // clang-format off
    std::vector<llvm::Type *> llvm_type_list = {
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt64Ty(llvm_context),
      llvm::Type::getInt16Ty(llvm_context),
      llvm::Type::getInt16Ty(llvm_context),
      llvm::Type::getInt8Ty(llvm_context),
      llvm::Type::getInt8Ty(llvm_context),
      llvm::Type::getInt8Ty(llvm_context)
    };
    // clang-format on

    auto llvm_struct = llvm::StructType::create(llvm_context, llvm_type_list,
                                                kTestStructureName, true);

    REQUIRE(llvm_struct != nullptr);

    auto llvm_module = createLLVMModule(llvm_context, "BPFModule");

    WHEN("determining the structure size") {
      auto structure_size =
          getLLVMStructureSize(llvm_struct, llvm_module.get());

      THEN("the amount of bytes required to hold it in memory is returned") {
        REQUIRE(structure_size == 39);
      }
    }

    WHEN("creating a syscall event function") {
      static const std::string kTestFunctionName{"TestFunction"};

      auto event_function_exp = createSyscallEventFunction(
          llvm_module.get(), kTestFunctionName, kTestStructureName);

      REQUIRE(event_function_exp.succeeded());

      auto function = event_function_exp.takeValue();
      REQUIRE(function != nullptr);

      auto function_name = function->getName();
      CHECK(function_name == kTestFunctionName);

      auto argument_count = function->arg_end() - function->arg_begin();
      CHECK(argument_count == 1U);

      const auto &argument = function->arg_begin();
      CHECK(argument->getName() == "args");
    }
  }
}
} // namespace ebpfpub
