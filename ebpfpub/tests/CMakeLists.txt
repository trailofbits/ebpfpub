#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable("ebpfpub-tests"
  src/main.cpp
  src/kallsymsparser.cpp
)

target_link_libraries("ebpfpub-tests" PRIVATE
  "ebpfpub_cxx_settings"
  "ebpfpub"
  "error"
  "external::doctest"
)

target_include_directories("ebpfpub-tests" PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)

add_custom_target("run-ebpfpub-tests"
  COMMAND "$<TARGET_FILE:ebpfpub-tests>"
  COMMENT "Running ebpfpub tests"
)
