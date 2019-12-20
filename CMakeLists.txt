cmake_minimum_required(VERSION 3.16.1)
include("cmake/version.cmake")

# This directory also takes care of the toolchain configuration
# so we have to include it before our project() declaration
add_subdirectory("libraries")

project("ebpfpub")

add_subdirectory("ebpfpub")
if(EBPFPUB_ENABLE_TOOLS)
  add_subdirectory("tools")
endif()
