/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <doctest/doctest.h>

#include "kallsymsparser.h"

namespace tob::ebpfpub {
SCENARIO("kallsyms parser") {
  GIVEN("a list of symbols") {
    // clang-format off
    const std::string kKallsymsExample = 
      "0000000000000000 A fixed_percpu_data\n"
      "0000000000000000 A __per_cpu_start\n"
      "0000000000000000 A cpu_debug_store\n"
      "0000000000000000 A irq_stack_backing_store\n"
      "0000000000000000 A cpu_tss_rw\n"
      "0000000000000000 A gdt_page\n"
      "0000000000000000 A exception_stacks\n"
      "0000000000000000 A entry_stack_storage\n"
      "0000000000000000 A espfix_waddr\n"
      "0000000000000000 A espfix_stack\n"
      "0000000000000000 t fuse_set_nowrite	[fuse]\n"
      "0000000000000000 t fuse_unlock_inode	[fuse]\n"
      "0000000000000000 t fuse_file_open	[fuse]\n"
      "0000000000000000 t fuse_abort_conn	[fuse]\n"
      "0000000000000000 t fuse_request_end	[fuse]\n"
      "0000000000000000 t fuse_update_ctime	[fuse]\n"
      "0000000000000000 t fuse_update_attributes	[fuse]\n"
      "0000000000000000 t fuse_open_common	[fuse]\n"
      "0000000000000000 t fuse_flush_writepages	[fuse]\n"
      "0000000000000000 t fuse_fill_super_common	[fuse]\n";
    // clang-format on

    const std::unordered_set<std::string> kExpectedSymbolNameList{
        "fixed_percpu_data",
        "__per_cpu_start",
        "cpu_debug_store",
        "irq_stack_backing_store",
        "cpu_tss_rw",
        "gdt_page",
        "exception_stacks",
        "entry_stack_storage",
        "espfix_waddr",
        "espfix_stack",
        "fuse_set_nowrite",
        "fuse_unlock_inode",
        "fuse_file_open",
        "fuse_abort_conn",
        "fuse_request_end",
        "fuse_update_ctime",
        "fuse_update_attributes",
        "fuse_open_common",
        "fuse_flush_writepages",
        "fuse_fill_super_common"};

    WHEN("obtaining the symbol list") {
      std::stringstream buffer;
      buffer.str(kKallsymsExample);

      auto symbol_list_exp = KallsymsParser::parseBuffer(std::move(buffer));

      REQUIRE(symbol_list_exp.succeeded());
      auto symbol_list = symbol_list_exp.takeValue();

      THEN("the symbol names are returned") {
        REQUIRE(symbol_list.size() == 20);

        for (const auto &expected_symbol_name : kExpectedSymbolNameList) {
          REQUIRE(symbol_list.count(expected_symbol_name) == 1);
        }
      }
    }
  }
}
} // namespace tob::ebpfpub
