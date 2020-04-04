#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

# This directory also takes care of the toolchain configuration
# so we have to include it before our project() declaration
add_subdirectory("libraries")

project("ebpfpub")
include("cmake/options.cmake")
include("cmake/version.cmake")

function(ebpfpubMain)
  add_subdirectory("ebpfpub")

  if(EBPFPUB_ENABLE_TOOLS)
    add_subdirectory("tools")
  endif()

  if(EBPFPUB_ENABLE_EXAMPLES)
    add_subdirectory("examples")
  endif()
endfunction()

ebpfpubMain()
