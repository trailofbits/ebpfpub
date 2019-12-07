cmake_minimum_required(VERSION 3.15.5)

macro(configureClangTidy)
  if(NOT EBPFPUB_ENABLE_CLANG_TIDY)
    message(STATUS "ebpfpub - clang-tidy: disabled")

  else()
    find_program(EBPFPUB_CLANG_TIDY_PATH "clang-tidy")
    if(NOT "${EBPFPUB_CLANG_TIDY_PATH}" STREQUAL "EBPFPUB_CLANG_TIDY_PATH-NOTFOUND")
      set(parameters "${EBPFPUB_CLANG_TIDY_PATH};${EBPFPUB_CLANG_TIDY_CHECKS}")

      set(CMAKE_C_CLANG_TIDY "${parameters}")
      set(CMAKE_CXX_CLANG_TIDY "${parameters}")

      message(STATUS "ebpfpub - clang-tidy: enabled (${EBPFPUB_CLANG_TIDY_PATH}, ${EBPFPUB_CLANG_TIDY_CHECKS})")

    else()
      message(WARNING "ebpfpub - clang-tidy: disabled (not found)")
    endif()
  endif()
endmacro()
