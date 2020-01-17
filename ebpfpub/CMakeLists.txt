#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.3)

function(ebpfpub)
  add_library(ebpfpub
    include/ebpfpub/ibpfprogramwriter.h
    include/ebpfpub/ibufferstorage.h
    include/ebpfpub/ifunctiontracer.h
    include/ebpfpub/iperfeventreader.h
    include/ebpfpub/isyscallserializer.h
    include/ebpfpub/ibufferreader.h

    src/bpfprogramwriter.h
    src/bpfprogramwriter.cpp

    src/syscallserializerfactory.h
    src/syscallserializerfactory.cpp

    src/genericsyscallserializer.h
    src/genericsyscallserializer.cpp

    src/connectsyscallserializer.h
    src/connectsyscallserializer.cpp

    src/perfeventreader.h
    src/perfeventreader.cpp

    src/bufferstorage.h
    src/bufferstorage.cpp

    src/functiontracer.h
    src/functiontracer.cpp

    src/bufferreader.h
    src/bufferreader.cpp

    src/abi.h
    src/abi.cpp
  )

  target_include_directories(ebpfpub
    PRIVATE include
    SYSTEM INTERFACE include
  )

  target_link_libraries(ebpfpub PUBLIC
    ebpf
    error
    utils
  )

  target_compile_definitions(ebpfpub PUBLIC
    EBPFPUB_VERSION="${EBPFPUB_VERSION}"
  )

  if(EBPFPUB_ENABLE_INSTALL)
    install(
      DIRECTORY "include/ebpfpub/"
      DESTINATION "include/ebpfpub"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      DIRECTORY "${CMAKE_SOURCE_DIR}/libraries/ebpf-common/src/ebpf/include/tob/ebpf/"
      DESTINATION "include/tob/ebpf"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      DIRECTORY "${CMAKE_SOURCE_DIR}/libraries/ebpf-common/src/error/include/tob/error/"
      DESTINATION "include/tob/error"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      DIRECTORY "${CMAKE_SOURCE_DIR}/libraries/ebpf-common/src/utils/include/tob/utils/"
      DESTINATION "include/tob/utils"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      TARGETS ebpfpub
      DESTINATION "lib"
    )
  endif()
endfunction()

ebpfpub()
