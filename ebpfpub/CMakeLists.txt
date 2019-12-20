cmake_minimum_required(VERSION 3.15.5)

function(ebpfpub)
  add_library(ebpfpub
    include/ebpfpub/ibufferstorage.h
    include/ebpfpub/isyscalltracepoint.h
    include/ebpfpub/iperfeventreader.h

    src/bpfprogramwriter.h
    src/bpfprogramwriter.cpp

    src/isyscallserializer.h

    src/syscallserializerfactory.h
    src/syscallserializerfactory.cpp

    src/genericsyscallserializer.h
    src/genericsyscallserializer.cpp

    src/connectsyscallserializer.h
    src/connectsyscallserializer.cpp

    src/bpfprogramresources.h
    src/bpfprogramresources.cpp

    src/perfeventreader.h
    src/perfeventreader.cpp

    src/bufferstorage.h
    src/bufferstorage.cpp

    src/syscalltracepoint.h
    src/syscalltracepoint.cpp

    src/bufferreader.h
    src/bufferreader.cpp
  )

  target_include_directories(ebpfpub
    PRIVATE include
    SYSTEM INTERFACE include
  )

  target_link_libraries(ebpfpub PUBLIC
    ebpf
    error
    utils
  )

  target_compile_definitions(ebpfpub PUBLIC
    EBPFPUB_VERSION="${EBPFPUB_VERSION}"
  )

  if(EBPFPUB_ENABLE_INSTALL)
    install(
      DIRECTORY "include/ebpfpub/"
      DESTINATION "include/ebpfpub"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      DIRECTORY "${CMAKE_SOURCE_DIR}/libraries/ebpf-common/src/ebpf/include/tob/ebpf/"
      DESTINATION "include/tob/ebpf"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      DIRECTORY "${CMAKE_SOURCE_DIR}/libraries/ebpf-common/src/error/include/tob/error/"
      DESTINATION "include/tob/error"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      DIRECTORY "${CMAKE_SOURCE_DIR}/libraries/ebpf-common/src/utils/include/tob/utils/"
      DESTINATION "include/tob/utils"
      FILES_MATCHING PATTERN "*.h"
    )

    install(
      TARGETS ebpfpub
      DESTINATION "lib"
    )
  endif()
endfunction()

ebpfpub()
