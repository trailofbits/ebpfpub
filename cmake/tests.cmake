cmake_minimum_required(VERSION 3.15.5)

set(EBPFPUB_TEST_RUNNER_TARGET "run_ebpfpub_tests")

function(generateRootTestTarget)
  if(NOT EBPFPUB_ENABLE_TESTS)
    message(STATUS "ebpfpub - Tests: disabled")

    add_custom_target(
      "${EBPFPUB_TEST_RUNNER_TARGET}"

      COMMAND "${CMAKE_COMMAND}" -E echo "ebpfpub - Tests are disabled. Enable them with -DEBPFPUB_ENABLE_TESTS:BOOL=True"
      VERBATIM
    )

    return()
  endif()

  message(STATUS "ebpfpub - Tests: enabled")
  add_custom_target("${EBPFPUB_TEST_RUNNER_TARGET}")
endfunction()

function(generateTestRunner target_name)
  if(NOT EBPFPUB_ENABLE_TESTS)
    return()
  endif()

  add_custom_target(
    "${target_name}_runner"
    COMMAND "$<TARGET_FILE:${target_name}>"
    COMMENT "Running: ${target_name}"
    VERBATIM
  )

  add_dependencies("${target_name}_runner" "${target_name}")
  add_dependencies("${EBPFPUB_TEST_RUNNER_TARGET}" "${target_name}_runner")
endfunction()

function(migrateTargetProperties destination_target source_target)
  set(property_list
    INTERFACE_INCLUDE_DIRECTORIES
    INTERFACE_LINK_LIBRARIES
    INTERFACE_COMPILE_DEFINITIONS
    INTERFACE_COMPILE_OPTIONS
  )

  get_target_property(source_target_type "${ARGS_SOURCE_TARGET}" TYPE)
  if(NOT "${source_target_type}" STREQUAL "INTERFACE_LIBRARY")
    list(APPEND property_list
      INCLUDE_DIRECTORIES
      LINK_LIBRARIES
      COMPILE_DEFINITIONS
      COMPILE_OPTIONS
    )
  endif()

  foreach(property_name ${property_list})
    unset(source_property_value)
    unset(new_property_value)

    get_target_property(source_property_value "${source_target}" "${property_name}")
    if("${source_property_value}" STREQUAL "source_property_value-NOTFOUND")
      continue()
    endif()

    string(REPLACE "INTERFACE_" "" destination_property_name "${property_name}")

    get_target_property(new_property_value "${destination_target}" "${destination_property_name}")
    if("${new_property_value}" STREQUAL "new_property_value-NOTFOUND")
      unset(new_property_value)
    endif()

    list(APPEND new_property_value ${source_property_value})
    set_target_properties("${destination_target}" PROPERTIES "${destination_property_name}" "${new_property_value}")
  endforeach()
endfunction()

function(addTargetTest)
  if(NOT EBPFPUB_ENABLE_TESTS)
    return()
  endif()

  cmake_parse_arguments(
    "ARGS"
    ""
    "SOURCE_TARGET"
    "SOURCES"
    ${ARGN}
  )

  if(NOT "${ARGS_UNPARSED_ARGUMENTS}" STREQUAL "")
    message(FATAL_ERROR "Invalid syntax")
  endif()

  get_target_property(source_target_type "${ARGS_SOURCE_TARGET}" TYPE)
  if(NOT "${source_target_type}" STREQUAL "INTERFACE_LIBRARY")
    get_target_property(main_target_sources "${ARGS_SOURCE_TARGET}" SOURCES)
    if("${main_target_sources}" STREQUAL "main_target_sources-NOTFOUND")
      message(FATAL_ERROR "Failed to import the source list from the main target")
    endif()

    list(REMOVE_ITEM main_target_sources "src/main.cpp")
  endif()

  set(test_target_name "${ARGS_SOURCE_TARGET}_tests")

  add_executable(
    "${test_target_name}"
    ${ARGS_SOURCES}
    ${main_target_sources}
  )

  target_link_libraries("${test_target_name}" PRIVATE
    thirdparty_catch2
  )

  get_target_property(source_target_type "${ARGS_SOURCE_TARGET}" TYPE)
  if(NOT "${source_target_type}" STREQUAL "INTERFACE_LIBRARY")
    get_target_property(source_target_folder ${ARGS_SOURCE_TARGET} SOURCE_DIR)

    target_include_directories("${test_target_name}" PRIVATE
      "${source_target_folder}/src"
    )
  endif()

  migrateTargetProperties(
    "${test_target_name}"
    "${ARGS_SOURCE_TARGET}"
  )

  generateTestRunner("${test_target_name}")
endfunction()
