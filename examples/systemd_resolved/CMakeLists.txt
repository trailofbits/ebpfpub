#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable("systemd_resolved"
  src/main.cpp
)

target_link_libraries("systemd_resolved" PRIVATE
  "ebpfpub_cxx_settings"
  "ebpfpub"
)
