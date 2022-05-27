#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

find_package(Qt5 COMPONENTS Core Widgets REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_executable("SocketMonitor"
  src/main.cpp

  src/mainwindow.h
  src/mainwindow.cpp

  src/tracer.h
  src/tracer.cpp

  src/model.h
  src/model.cpp
)

target_link_libraries("SocketMonitor" PRIVATE
  "ebpfpub_cxx_settings"
  "ebpfpub"
  "Qt5::Widgets"
)
