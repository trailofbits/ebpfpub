cmake_minimum_required(VERSION 3.15.5)
project("CLI11")

function(ebpfpubLibrariesCLI11)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_cli11 INTERFACE)
  target_include_directories(thirdparty_cli11 SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

ebpfpubLibrariesCLI11()
