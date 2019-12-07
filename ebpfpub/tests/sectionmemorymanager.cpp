#include <sectionmemorymanager.h>

#include <catch2/catch.hpp>

#include <llvm/IR/IRBuilder.h>

namespace ebpfpub {
SCENARIO("Saving memory sections from the execution engine",
         "[SectionMemoryManager]") {

  MemorySectionMap memory_section_map;
  SectionMemoryManager section_memory_manager(memory_section_map);

  GIVEN("An initialized SectionMemoryManager object") {
    WHEN("code and data sections are allocated") {
      auto code_section = section_memory_manager.allocateCodeSection(
          1024U, sizeof(void *), 0U, "FirstSection");

      auto data_section = section_memory_manager.allocateDataSection(
          1024U, sizeof(void *), 1U, "SecondSection", true);

      section_memory_manager.finalizeMemory();

      THEN("section buffers are captured") {
        REQUIRE(code_section != nullptr);
        REQUIRE(data_section != nullptr);

        REQUIRE(memory_section_map.size() == 2U);

        auto first_section_it = memory_section_map.find("FirstSection");
        REQUIRE(first_section_it != memory_section_map.end());

        auto second_section_it = memory_section_map.find("SecondSection");
        REQUIRE(second_section_it != memory_section_map.end());

        const auto &generated_code_section = first_section_it->second;
        const auto &generated_data_section = second_section_it->second;

        REQUIRE(generated_code_section.type == MemorySection::Type::Code);
        REQUIRE(generated_data_section.type == MemorySection::Type::Data);

        REQUIRE(generated_code_section.read_only == false);
        REQUIRE(generated_data_section.read_only == true);

        REQUIRE(generated_code_section.alignment == 8U);
        REQUIRE(generated_data_section.alignment == 8U);

        REQUIRE(generated_code_section.id == 0U);
        REQUIRE(generated_data_section.id == 1U);

        REQUIRE(generated_code_section.data.size() == 1024U);
        REQUIRE(generated_data_section.data.size() == 1024U);
      }
    }
  }
}
} // namespace ebpfpub
