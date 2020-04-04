#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)
project("ebpfpub")

include("../cmake/version.cmake")

set(EBPFPUB_INSTALL_PATH "" CACHE STRING "This is the path where ebpfpub has been installed")
set(PACKAGE_VERSION 1)

string(REPLACE "." ";" EBPFPUB_VERSION_COMPONENTS "${EBPFPUB_VERSION}")
list(GET EBPFPUB_VERSION_COMPONENTS 0 CPACK_PACKAGE_VERSION_MAJOR)
list(GET EBPFPUB_VERSION_COMPONENTS 1 CPACK_PACKAGE_VERSION_MINOR)
list(GET EBPFPUB_VERSION_COMPONENTS 2 CPACK_PACKAGE_VERSION_PATCH)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ebpfpub is both a library and a command line tools to trace system call tracepoints using eBPF.")
set(CPACK_PACKAGE_NAME "ebpfpub")
set(CPACK_PACKAGE_VENDOR "Trail of Bits")
set(CPACK_PACKAGE_CONTACT "info@trailofbits.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.trailofbits.com")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${EBPFPUB_VERSION}-${PACKAGE_VERSION}.x86_64")
set(CPACK_PACKAGE_RELOCATABLE ON)

set(CPACK_DEBIAN_PACKAGE_RELEASE "${PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_SECTION "default")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>=2.12)")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")

set(CPACK_RPM_PACKAGE_RELEASE_DIST "${PACKAGE_VERSION}")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_PACKAGE_GROUP "default")
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.12")

function(ebpfpubPackageGenerator)
  if("${EBPFPUB_INSTALL_PATH}" STREQUAL "")
    message(FATAL_ERROR "The EBPFPUB_INSTALL_PATH parameter is mandatory")
  endif()

  if(NOT EXISTS "${EBPFPUB_INSTALL_PATH}/usr/local/lib/libebpfpub.a")
    message(FATAL_ERROR "The provided EBPFPUB_INSTALL_PATH parameter is not valid")
  endif()

  install(
    FILES
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/ebpfpub/ibpfprogramwriter.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/ebpfpub/ibufferreader.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/ebpfpub/ibufferstorage.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/ebpfpub/ifunctionserializer.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/ebpfpub/ifunctiontracer.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/ebpfpub/iperfeventreader.h"

    DESTINATION
      "include/ebpfpub"
  )

  install(
    FILES
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/types.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/sectionmemorymanager.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/bpfmap.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/bpfsyscallinterface.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/structure.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/ebpf_utils.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/typedbpfmap.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/llvm_utils.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/perfeventarray.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/tracepointdescriptor.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/ebpf/iperfevent.h"

    DESTINATION
      "include/tob/ebpf"
  )


  install(
    FILES
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/error/errorcode.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/error/erroror.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/error/error.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/error/successor.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/error/stringerror.h"

    DESTINATION
      "include/tob/error"
  )


  install(
    FILES
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/utils/ielfimage.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/utils/uniquefd.h"
      "${EBPFPUB_INSTALL_PATH}/usr/local/include/tob/utils/uniqueref.h"

    DESTINATION
      "include/tob/utils"
  )

  install(
    FILES
      "${EBPFPUB_INSTALL_PATH}/usr/local/lib/libebpfpub.a"

    DESTINATION
      "lib"
  )

  install(
    FILES
      "${EBPFPUB_INSTALL_PATH}/usr/local/bin/ebpftracer"

    DESTINATION
      "bin"

    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_WRITE GROUP_EXECUTE
                WORLD_READ             WORLD_EXECUTE
  )
endfunction()

set(CPACK_GENERATOR "TGZ")

unset(rpm_executable_path CACHE)
find_program(rpm_executable_path "rpm")
if("${rpm_executable_path}" STREQUAL "rpm_executable_path-NOTFOUND")
  message(WARNING "ebpfpub - The RPM package generator requires the 'rpm' tool")
else()
  list(APPEND CPACK_GENERATOR "RPM")
  message(STATUS "ebpfpub - The RPM generator has been enabled")
endif()

unset(dpkg_executable_path CACHE)
find_program(dpkg_executable_path "dpkg")
if("${dpkg_executable_path}" STREQUAL "dpkg_executable_path-NOTFOUND")
  message(WARNING "ebpfpub - The DEB package generator requires the 'dpkg' tool")
else()
  list(APPEND CPACK_GENERATOR "DEB")
  message(STATUS "ebpfpub - The DEB generator has been enabled")
endif()

include(CPack)

ebpfpubPackageGenerator()
