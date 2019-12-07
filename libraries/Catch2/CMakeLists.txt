cmake_minimum_required(VERSION 3.15.5)
project("catch2")

function(ebpfpubLibrariesCatch2)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_catch2 INTERFACE)
  target_include_directories(thirdparty_catch2 SYSTEM INTERFACE
    "${library_root}/single_include"
  )
endfunction()

ebpfpubLibrariesCatch2()
