#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(NOT DEFINED ENV{TOOLCHAIN_PATH})
  message(FATAL_ERROR "The toolchain path is not set. Please set the 'TOOLCHAIN_PATH' environment variable and try again")
endif()

set(TOOLCHAIN_PATH "$ENV{TOOLCHAIN_PATH}")
set(CMAKE_SYSROOT "${TOOLCHAIN_PATH}")

set(CMAKE_C_COMPILER "${TOOLCHAIN_PATH}/usr/bin/clang")
set(CMAKE_C_IMPLICIT_LINK_DIRECTORIES "${TOOLCHAIN_PATH}/usr/lib ${TOOLCHAIN_PATH}/lib")

set(CMAKE_CXX_COMPILER "${TOOLCHAIN_PATH}/usr/bin/clang++")
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")

set(CMAKE_EXE_LINKER_FLAGS_INIT "${TOOLCHAIN_PATH}/usr/lib/libc++abi.a ${TOOLCHAIN_PATH}/usr/lib/librt.a")

set(CMAKE_LINK_SEARCH_START_STATIC true)
set(CMAKE_LINK_SEARCH_END_STATIC true)

set(CMAKE_CXX_LINK_NO_PIE_SUPPORTED true)
set(CMAKE_CXX_LINK_PIE_SUPPORTED true)

set(CMAKE_C_LINK_NO_PIE_SUPPORTED true)
set(CMAKE_C_LINK_PIE_SUPPORTED true)
