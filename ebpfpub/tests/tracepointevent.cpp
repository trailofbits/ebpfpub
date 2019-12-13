/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "tracepointevent.h"

#include <catch2/catch.hpp>

namespace ebpfpub {
SCENARIO("The TracepointEvent class can open, parse and convert tracepoint "
         "parameters",
         "[TracepointEvent]") {

  GIVEN("A category and name") {
    const std::string category{"syscalls"};
    const std::string name{"sys_enter_open"};

    WHEN("determining the tracepoint event paths") {
      auto path_map = TracepointEvent::getTracepointPathMap(category, name);

      THEN("the category and event name are concatenated to form the absolute "
           "paths") {

        // clang-format off
        const TracepointEvent::PathMap kExpectedPathMap = {
          { TracepointEvent::PathType::Root, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_open" },
          { TracepointEvent::PathType::EnableSwitch, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_open/enable" },
          { TracepointEvent::PathType::Format, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format" },
          { TracepointEvent::PathType::EventIdentifier, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_open/id" },
        };
        // clang-format on

        REQUIRE(path_map.size() == kExpectedPathMap.size());

        for (const auto &p : kExpectedPathMap) {
          const auto &path_type = p.first;
          const auto &expected_path = p.second;

          auto it = path_map.find(path_type);
          REQUIRE(it != path_map.end());

          const auto &returned_path = it->second;
          REQUIRE(returned_path == expected_path);
        }
      }
    }
  }

  GIVEN("The contents of a tracepoint format file") {
    // clang-format off
    const std::string tracepoint_format{
      "name: sys_enter_open\n"
      "ID: 606\n"
      "format:\n"
      "  field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
      "  field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
      "  field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
      "  field:int common_pid;	offset:4;	size:4;	signed:1;\n"
      "\n"
      "  field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
      "  field:const char __attribute__((user)) * filename;	offset:16;	size:8;	signed:0;\n"
      "  field:int flags;	offset:24;	size:8;	signed:0;\n"
      "  field:umode_t mode;	offset:32;	size:8;	signed:0;\n"
      "\n"
      "print fmt: \"filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx\", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))\n"
    };
    // clang-format on

    WHEN("parsing the whole file") {
      auto structure_exp =
          TracepointEvent::parseTracepointEventFormat(tracepoint_format);

      REQUIRE(structure_exp.succeeded());

      auto structure = structure_exp.takeValue();

      THEN("only the actual tracepoint parameters are processed") {
        // clang-format off
        const TracepointEvent::Structure expected_structure_data = {
          { "unsigned short", "common_type", 0U, 2U, false},
          { "unsigned char", "common_flags", 2U, 1U, false},
          { "unsigned char", "common_preempt_count", 3U, 1U, false},
          { "int", "common_pid", 4U, 4U, true},

          { "int", "__syscall_nr", 8U, 4U, true },
          { "const char *", "filename", 16U, 8U, false },
          { "int", "flags", 24U, 8U, false },
          { "umode_t", "mode", 32U, 8U, false }
        };
        // clang-format on

        REQUIRE(structure.size() == expected_structure_data.size());

        for (auto i = 0U; i < expected_structure_data.size(); ++i) {
          const auto &parsed_field = structure.at(i);
          const auto &expected_field = expected_structure_data.at(i);

          REQUIRE(parsed_field.type == expected_field.type);
          REQUIRE(parsed_field.name == expected_field.name);
          REQUIRE(parsed_field.offset == expected_field.offset);
          REQUIRE(parsed_field.size == expected_field.size);
          REQUIRE(parsed_field.is_signed == expected_field.is_signed);
        }
      }
    }
  }
}
} // namespace ebpfpub
