#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

function(ebpfpubExamples)
  if(EBPFPUB_BUILD_EXAMPLES)
    message(STATUS "ebpfpub - Examples are being built")

    add_subdirectory("sample1")
    add_subdirectory("execsnoop")
  endif()

  if(EBFPPUB_BUILD_SOCKETMONITOR_EXAMPLE)
    message(STATUS "ebpfpub - The SocketMonitor example is being built")
    add_subdirectory("SocketMonitor")
  endif()
endfunction()

ebpfpubExamples()
