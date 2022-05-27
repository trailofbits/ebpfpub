#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.22.1)
project("ebpfpub")

include("cmake/options.cmake")
include("cmake/version.cmake")
include("cmake/settings.cmake")

add_subdirectory("libraries")
add_subdirectory("ebpfpub")
add_subdirectory("examples")
