cmake_minimum_required(VERSION 3.15.5)
project("ebpfpub")

include(cmake/options.cmake)
include(cmake/clang-tidy.cmake)
include(cmake/sanitizers.cmake)
include(cmake/tests.cmake)

function(ebpfpubMain)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE STRING "Set to ON to export the compile_commands.json file" FORCE)

  message(STATUS "ebpfpub - Build type: ${CMAKE_BUILD_TYPE}")
  message(STATUS "ebpfpub - Install target: ${EBPFPUB_ENABLE_INSTALL}")

  defineSettingsTargets()
  generateRootTestTarget()

  add_subdirectory("libraries")
  add_subdirectory("ebpfpub")
  add_subdirectory("tools")
endfunction()

function(defineSettingsTargets)
  add_library(ebpfpub_common_settings INTERFACE)
  target_compile_options(ebpfpub_common_settings INTERFACE
    -Wall
    -pedantic
    -Wconversion
    -Wunused
    -Wshadow
    -fvisibility=hidden
    -Werror
    -Wno-deprecated-declarations
  )

  set_target_properties(ebpfpub_common_settings PROPERTIES
    INTERFACE_POSITION_INDEPENDENT_CODE ON
  )

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND compile_option_list -O0)
    list(APPEND compile_definition_list DEBUG)

  else()
    list(APPEND compile_option_list -O2)
    list(APPEND compile_definition_list NDEBUG)
  endif()


  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    list(APPEND compile_option_list -g3)
  else()
    list(APPEND compile_option_list -g0)
  endif()

  target_compile_options(ebpfpub_common_settings INTERFACE
    ${compile_option_list}
  )

  target_compile_definitions(ebpfpub_common_settings INTERFACE
    ${compile_definition_list}
  )

  configureSanitizers("ebpfpub_common_settings")

  add_library(ebpfpub_cxx_settings INTERFACE)
  target_compile_features(ebpfpub_cxx_settings INTERFACE cxx_std_17)
  target_link_libraries(ebpfpub_cxx_settings INTERFACE ebpfpub_common_settings)

  add_library(ebpfpub_c_settings INTERFACE)
  target_link_libraries(ebpfpub_c_settings INTERFACE ebpfpub_common_settings)
endfunction()

configureClangTidy()
ebpfpubMain()
