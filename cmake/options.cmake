#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.15.5)

if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release" AND
   NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND
   NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")

  set(default_cmake_build_type "RelWithDebInfo")

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
    message(WARNING "Invalid build type specified: ${CMAKE_BUILD_TYPE}")
  endif()

  message(WARNING "Setting CMAKE_BUILD_TYPE to ${default_cmake_build_type}")
  set(CMAKE_BUILD_TYPE "${default_cmake_build_type}" CACHE STRING "Build type (default ${default_cmake_build_type})" FORCE)
endif()

option(EBPFPUB_ENABLE_TESTS "Set to ON to build the tests")
option(EBPFPUB_ENABLE_INSTALL "Set to ON to generate the install directives")
option(EBPFPUB_ENABLE_SANITIZERS "Set to ON to enable sanitizers. Only available when compiling with Clang")
option(EBPFPUB_ENABLE_LIBCPP "Set to ON to enable libc++")
option(EBPFPUB_ENABLE_TOOLS "Set to ON to enable tools")

option(EBPFPUB_ENABLE_CLANG_TIDY "Enables clang-tidy support")
set(EBPFPUB_CLANG_TIDY_CHECKS "-checks=cert-*,cppcoreguidelines-*,performance-*,portability-*,readability-*,modernize-*" CACHE STRING "List of checks performed by clang-tidy")

set(EBPFPUB_TOOLCHAIN_PATH "" CACHE PATH "Toolchain path")

if(NOT "${EBPFPUB_TOOLCHAIN_PATH}" STREQUAL "")
  if(NOT EXISTS "${EBPFPUB_TOOLCHAIN_PATH}")
    message(FATAL_ERROR "ebpfpub - The specified toolchain path is not valid: ${EBPFPUB_TOOLCHAIN_PATH}")
  endif()

  message(STATUS "ebpfpub - Using toolchain path '${EBPFPUB_TOOLCHAIN_PATH}'. Forcing EBPFPUB_ENABLE_LIBCPP to ON")

  set(CMAKE_C_COMPILER "${EBPFPUB_TOOLCHAIN_PATH}/usr/bin/clang" CACHE PATH "Path to the C compiler" FORCE)
  set(CMAKE_CXX_COMPILER "${EBPFPUB_TOOLCHAIN_PATH}/usr/bin/clang++" CACHE PATH "Path to the C++ compiler" FORCE)

  set(CMAKE_SYSROOT "${EBPFPUB_TOOLCHAIN_PATH}" CACHE PATH "CMake sysroot for find_package scripts")
  set(EBPFPUB_ENABLE_LIBCPP ON CACHE BOOL "Set to ON to enable libc++" FORCE)
endif()
