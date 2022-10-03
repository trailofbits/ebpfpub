#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(NOT TARGET "thirdparty_doctest")
  add_library("thirdparty_doctest" INTERFACE)
  target_include_directories("thirdparty_doctest" INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  add_library("external::doctest" ALIAS "thirdparty_doctest")
endif()
