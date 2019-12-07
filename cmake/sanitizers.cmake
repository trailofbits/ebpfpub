cmake_minimum_required(VERSION 3.15.5)

function(configureSanitizers target_name)
  if(NOT EBPFPUB_ENABLE_SANITIZERS)
  message(STATUS "ebpfpub - Sanitizers: disabled")
    return()
  endif()

  if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    message(STATUS "ebpfpub - Sanitizers: disabled (not supported)")
    return()
  endif()

  set(flag_list
    -fno-omit-frame-pointer -fsanitize=undefined,address
  )

  target_compile_options("${target_name}" INTERFACE ${flag_list})
  target_link_options("${target_name}" INTERFACE ${flag_list})

  message(STATUS "ebpfpub - Sanitizers: enabled")

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message(WARNING "ebpfpub - Debug builds are preferred when using sanitizers")
  endif()
endfunction()
