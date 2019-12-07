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
option(EBPFPUB_ENABLE_LIBCPP "Set to ON to enable libc++.")

option(EBPFPUB_ENABLE_CLANG_TIDY "Enables clang-tidy support")
set(EBPFPUB_CLANG_TIDY_CHECKS "-checks=cert-*,cppcoreguidelines-*,performance-*,portability-*,readability-*,modernize-*" CACHE STRING "List of checks performed by clang-tidy")
