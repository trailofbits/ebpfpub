#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

function(ebpfpub)
  add_library(ebpfpub
    include/ebpfpub/ibufferstorage.h
    include/ebpfpub/iperfeventreader.h

    include/ebpfpub/ifunctiontracer.h
    src/ifunctiontracer.cpp

    src/perfeventreader.h
    src/perfeventreader.cpp

    src/bufferstorage.h
    src/bufferstorage.cpp

    src/forknamespacehelper.h
    src/forknamespacehelper.cpp

    src/functiontracer.h
    src/functiontracer.cpp

    src/bufferreader.h
    src/bufferreader.cpp

    src/abi.h
    src/abi.cpp

    src/tracepointserializers.h
    src/tracepointserializers.cpp

    src/kallsymsparser.h
    src/kallsymsparser.cpp

    src/llvm_compat.h
    src/llvm_compat.cpp
  )

  target_include_directories(ebpfpub
    PRIVATE include
  )

  target_include_directories(ebpfpub
    SYSTEM INTERFACE include
  )

  target_link_libraries(ebpfpub
    PRIVATE
      cxx_target_settings

    PUBLIC
      ebpf
      error
      utils
  )

  target_compile_definitions(ebpfpub PUBLIC
    EBPFPUB_VERSION="${EBPFPUB_VERSION}"
    LLVM_MAJOR_VERSION="${LLVM_MAJOR_VERSION}"
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

  if(EBPFPUB_ENABLE_TESTS)
    add_subdirectory("tests")
  endif()
endfunction()

ebpfpub()
