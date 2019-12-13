#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.15.5)
project("LLVM")

function(ebpfpubLibrariesLLVM)
  find_package(LLVM REQUIRED)

  add_library(thirdparty_llvm INTERFACE)
  target_link_libraries(thirdparty_llvm INTERFACE
    LLVMMCJIT
    LLVMBPFCodeGen
    LLVMX86CodeGen
  )

  # Ubuntu/Debian workarounds
  if(EXISTS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
    list(APPEND LLVM_INCLUDE_DIRS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
  endif()

  target_include_directories(thirdparty_llvm SYSTEM INTERFACE
    ${LLVM_INCLUDE_DIRS}
  )

  target_compile_definitions(thirdparty_llvm INTERFACE
    ${LLVM_DEFINITIONS}
  )
endfunction()

ebpfpubLibrariesLLVM()
