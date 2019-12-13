cmake_minimum_required(VERSION 3.15.5)

function(ebpfpub)
  add_library(ebpfpub
    include/ebpfpub/error.h
    include/ebpfpub/erroror.h
    include/ebpfpub/errorcode.h
    include/ebpfpub/successor.h
    include/ebpfpub/ibufferstorage.h
    include/ebpfpub/isyscalltracepoint.h
    include/ebpfpub/itracepointevent.h
    include/ebpfpub/iperfeventarray.h
    include/ebpfpub/iperfeventreader.h
    include/ebpfpub/uniqueref.h

    include/ebpfpub/stringerror.h
    src/stringerror.cpp

    src/bpfprogramwriter.h
    src/bpfprogramwriter.cpp

    src/isyscallserializer.h

    src/syscallserializerfactory.h
    src/syscallserializerfactory.cpp

    src/genericsyscallserializer.h
    src/genericsyscallserializer.cpp

    src/connectsyscallserializer.h
    src/connectsyscallserializer.cpp

    src/bpfmap.h
    src/typedbpfmap.h

    src/bpfprogramresources.h
    src/bpfprogramresources.cpp

    src/bpfprograminstance.h
    src/bpfprograminstance.cpp

    src/perfeventreader.h
    src/perfeventreader.cpp

    src/bpfoutput.h
    src/bpfoutput.cpp

    src/uniquefd.h
    src/uniquefd.cpp

    src/uniquemappedmemory.h
    src/uniquemappedmemory.cpp

    src/bufferstorage.h
    src/bufferstorage.cpp

    src/syscalltracepoint.h
    src/syscalltracepoint.cpp

    src/tracepointevent.h
    src/tracepointevent.cpp

    src/perfeventarray.h
    src/perfeventarray.cpp

    src/sectionmemorymanager.h
    src/sectionmemorymanager.cpp

    src/llvm_utils.h
    src/llvm_utils.cpp

    src/bufferreader.h
    src/bufferreader.cpp
  )

  target_include_directories(ebpfpub
    PRIVATE include
    SYSTEM INTERFACE include
  )

  target_link_libraries(ebpfpub PUBLIC
    ebpfpub_cxx_settings
    thirdparty_llvm
    thirdparty_libbpf
  )

  addTargetTest(
    SOURCE_TARGET
      ebpfpub
  
    SOURCES
      tests/main.cpp
      tests/tracepointevent.cpp
      tests/bpfmap.cpp
      tests/typedbpfmap.cpp
      tests/sectionmemorymanager.cpp
      tests/llvm_utils.cpp
      tests/uniqueref.cpp
      tests/erroror.cpp
  )

  if(EBPFPUB_ENABLE_INSTALL)
    install(
      DIRECTORY "include/ebpfpub/"
      DESTINATION "include/ebpfpub"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      TARGETS ebpfpub
      DESTINATION "lib"
    )
  endif()
endfunction()

ebpfpub()
