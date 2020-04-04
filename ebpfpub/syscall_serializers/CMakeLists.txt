#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

function(ebpfpubSrcSyscallSerializers)
  add_library(syscall_serializers
    include/ebpfpub/serializers/genericsyscallserializer.h
    src/genericsyscallserializer.cpp
    
    include/ebpfpub/serializers/connectsyscallserializer.h
    src/connectsyscallserializer.cpp

    include/ebpfpub/serializers/execvesyscallserializer.h
    src/execvesyscallserializer.cpp
  )

  target_include_directories(syscall_serializers PRIVATE
    include
  )

  target_include_directories(syscall_serializers SYSTEM INTERFACE
    include
  )

  target_link_libraries(syscall_serializers PRIVATE
    ebpfpub
  )
endfunction()

ebpfpubSrcSyscallSerializers()
