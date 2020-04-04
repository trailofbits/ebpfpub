#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

function(ebpfpubLibraries)
  add_subdirectory("ebpf-common")
  add_subdirectory("CLI11")
endfunction()

ebpfpubLibraries()
