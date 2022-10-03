#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(EBPFPUB_ENABLE_EXAMPLES)
  message(STATUS "ebpfpub - Examples are being built")

  add_subdirectory("socketevents")
  add_subdirectory("execsnoop")
  add_subdirectory("readline_trace")
  add_subdirectory("kprobe_execsnoop")
  add_subdirectory("systemd_resolved")
endif()
