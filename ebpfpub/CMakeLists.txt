#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library("ebpfpub"
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

  src/abi.h
  src/abi.cpp

  src/tracepointserializers.h
  src/tracepointserializers.cpp

  src/kallsymsparser.h
  src/kallsymsparser.cpp

  src/llvm_compat.h
  src/llvm_compat.cpp
)

target_include_directories("ebpfpub" PRIVATE
  include
)

target_include_directories("ebpfpub" SYSTEM INTERFACE
  include
)

target_link_libraries("ebpfpub"
  PRIVATE
    "ebpfpub_cxx_settings"

  PUBLIC
    "ebpf"
    "error"
    "utils"
    "btfparse"
)

target_compile_definitions("ebpfpub" PUBLIC
  EBPFPUB_VERSION="${EBPFPUB_VERSION}"
  LLVM_MAJOR_VERSION="${LLVM_MAJOR_VERSION}"
)

if(EBPFPUB_ENABLE_TESTS)
  add_subdirectory("tests")
endif()
