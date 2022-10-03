#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(NOT TARGET "ebpf" AND NOT TARGET "utils" AND NOT TARGET "error")
  add_subdirectory("ebpf-common")
endif()

if(EBPFPUB_ENABLE_TESTS)
  add_subdirectory("doctest")
endif()
