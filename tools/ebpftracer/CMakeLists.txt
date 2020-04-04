#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("ebpftracer")

function(ebpfpubToolsEbpftracer)
  add_executable(ebpftracer
    src/main.cpp

    src/configuration.h
    src/configuration.cpp

    src/utils.h
    src/utils.cpp
  )

  target_link_libraries(ebpftracer PRIVATE
    ebpfpub
    thirdparty_cli11
  )

  if(EBPFPUB_ENABLE_INSTALL)
    install(TARGETS "ebpftracer" DESTINATION "bin")
  endif()
endfunction()

ebpfpubToolsEbpftracer()
