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
* Optional, but highly recommended: download and install the osquery-toolchain (see below).
  * **This should work fine on any recent Linux distribution. The binaries generated with this toolchain are portable and can be deployed on any distro >= CentOS 6/Ubuntu 16.04**
* If _not_ using the osquery-toolchain (if building with the system toolchain):
  * **Clang and the C++ library must both support C++17**. Recent distributions should be compatible (tested on Arch Linux, Ubuntu 19.10 and above).
  * A recent Clang/LLVM installation (8.0 or better), compiled with BPF support.
    * Test for the support: `llc --version | grep bpf` and check that BPF is listed as a registered target.
    * Please note that LLVM itself must be compiled with libc++ when enabling the `EBPF_COMMON_ENABLE_LIBCPP` option, since ebfpub will directly link against the LLVM libraries.
  * The packages `llvm-devel` (for `LLVMConfig.cmake` files), `llvm-static` (for additional LLVM libraries), and `ncurses-devel` (for `libtinfo`)

#### Installing the osquery-toolchain

As root:
```shell
cd /tmp
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz 
tar -xf /tmp/ebpfpub/build/osquery-toolchain-1.1.0-x86_64.tar.xz -C /opt
```

### Dependencies (retrieved with git)

* [ebpf-common](https://github.com/trailofbits/ebpf-common)

### Steps to Build

1. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfpub`
2. If you cloned the repo without the `--recursive` flag, run `git submodule update --init --recursive`
3. Enter the source folder: `cd ebpfpub`
4. If you intend to build the project using the osquery-toolchain: `export TOOLCHAIN_PATH="/opt/osquery-toolchain"`, then add `-DCMAKE_TOOLCHAIN_FILE=cmake/toolchain.cmake` to step 6
5. Configure the project: `cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEBPFPUB_ENABLE_INSTALL=true -DEBPFPUB_ENABLE_EXAMPLES=true -DEBPF_COMMON_ENABLE_TESTS=true`
6. Build the project: `cmake --build build -j $(($(nproc) + 1))`
7. Run the tests: `cmake --build build --target run-ebpf-common-tests`

## Building the package

### Prerequisites for packaging

* DEB: **dpkg** command
* RPM: **rpm** command
* TGZ: **tar** command

### Steps to package

Make sure that the `-DEBPFPUB_ENABLE_INSTALL:BOOL=true` parameter has been passed at configure time, then run the following commands inside the build folder:

```shell
mkdir install
export DESTDIR=`realpath install`

cd build
cmake --build . --target install
```

Configure the packaging project:

```shell
mkdir package
cd package

cmake -DEBPFPUB_INSTALL_PATH:PATH="${DESTDIR}" /path/to/source_folder/package_generator
cmake --build . --target package
```
