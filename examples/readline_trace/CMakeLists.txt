#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("readline_trace")

function(ebpfpubExamplesReadlineTrace)
  add_executable("${PROJECT_NAME}"
    src/main.cpp
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    cxx_target_settings
    ebpfpub
  )
endfunction()

ebpfpubExamplesReadlineTrace()

