# ebpfpub

ebpfpub is a generic function tracing library for Linux that supports tracepoints, kprobes and uprobes.

| | |
|-|-|
| CI Status | ![](https://github.com/trailofbits/ebpfpub/workflows/Build/badge.svg) |

## Building

### Prerequisites
* A recent libc++ or stdc++ library, supporting C++17
* CMake >= 3.16.2. A pre-built binary can be downloaded from the [CMake's download page](https://cmake.org/download/).
* Linux kernel >= 4.18 (Ubuntu 18.10, CentOS 8, Red Hat Enterprise Linux 8).
  * Test for the support: ``grep BPF /boot/config-`uname -r` `` and check the output for `CONFIG_BPF=y` and `CONFIG_BPF_SYSCALL=y`
* The package `libz-dev`, needed during linking.
* Optional, but highly recommended: Download the osquery-toolchain: https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz
  * **This should work fine on any recent Linux distribution. The binaries generated with this toolchain are portable and can be deployed on any distro >= CentOS 6/Ubuntu 16.04**
* If _not_ using the osquery-toolchain (if building with the system toolchain):
  * **Clang and the C++ library must both support C++17**. Recent distributions should be compatible (tested on Arch Linux, Ubuntu 19.10 and above).
  * A recent Clang/LLVM installation (8.0 or better), compiled with BPF support.
    * Test for the support: `llc --version | grep bpf` and check that BPF is listed as a registered target.
    * Please note that LLVM itself must be compiled with libc++ when enabling the `EBPF_COMMON_ENABLE_LIBCPP` option, since ebfpub will directly link against the LLVM libraries.
  * The packages `llvm-devel` (for `LLVMConfig.cmake` files), `llvm-static` (for additional LLVM libraries), and `ncurses-devel` (for `libtinfo`)

### Dependencies (retrieved with git)
* [ebpf-common](https://github.com/trailofbits/ebpf-common)

### Steps to Build

1. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfpub`
2. In case the `--recursive` flag was not provided, run `git submodule update --init --recursive`
3. Enter the source folder: `cd ebpfpub`
4. Create the build folder: `mkdir build && cd build`
5. Configure the project: `cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DEBPF_COMMON_TOOLCHAIN_PATH:PATH=/path/to/osquery-toolchain -DEBPFPUB_ENABLE_INSTALL:BOOL=true -DEBPFPUB_ENABLE_EXAMPLES:BOOL=true -DEBPF_COMMON_ENABLE_TESTS:BOOL=true ..`
(remove `-DEBPF_COMMON_TOOLCHAIN_PATH:PATH=/path/to/osquery-toolchain` if you are building with the system toolchain)
6. Build the project: `cmake --build . -j $(($(nproc) + 1))`
7. Run the tests: `cmake --build . --target run-ebpf-common-tests`

### Building the packages

## Prerequisites
* DEB: **dpkg** command
* RPM: **rpm** command
* TGZ: **tar** command

## Steps
Make sure that the `-DEBPFPUB_ENABLE_INSTALL:BOOL=true` parameter has been passed at configure time, then run the following commands inside the build folder:

```
mkdir install
export DESTDIR=`realpath install`

cd build
cmake --build . --target install
```

Configure the packaging project:

```
mkdir package
cd package

cmake -DEBPFPUB_INSTALL_PATH:PATH="${DESTDIR}" /path/to/source_folder/package_generator
cmake --build . --target package
```
