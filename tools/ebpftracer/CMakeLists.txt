cmake_minimum_required(VERSION 3.15.5)
project("ebpftracer")

function(toolsEbpftracer)
  add_executable(ebpftracer
    src/main.cpp

    src/configuration.h
    src/configuration.cpp

    src/utils.h
    src/utils.cpp
  )

  target_link_libraries(ebpftracer PRIVATE
    ebpfpub_cxx_settings
    ebpfpub
    thirdparty_cli11
  )
endfunction()


toolsEbpftracer()
