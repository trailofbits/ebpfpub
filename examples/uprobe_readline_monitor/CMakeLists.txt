#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.15.5)
project("uprobe_readline_monitor")

function(ebpfpubExamplesUprobeReadlineMonitor)
  add_executable(uprobe_readline_monitor
    src/main.cpp
  )

  target_link_libraries(uprobe_readline_monitor PRIVATE
    ebpfpub
    thirdparty_cli11
  )
endfunction()

ebpfpubExamplesUprobeReadlineMonitor()
