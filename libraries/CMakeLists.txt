cmake_minimum_required(VERSION 3.15.5)

function(ebpfpubLibraries)
  add_subdirectory("LLVM")
  add_subdirectory("CLI11")

  if(EBPFPUB_ENABLE_TESTS)
    add_subdirectory("Catch2")
  endif()
endfunction()

ebpfpubLibraries()
