# ebpfpub

ebpfpub is a generic function tracing library for Linux that supports tracepoints, kprobes and uprobes.

| | |
|-|-|
| CI Status | ![](https://github.com/trailofbits/ebpfpub/workflows/Build/badge.svg) |

## Building

### Prerequisites
* A recent Clang/LLVM installation (8.0 or better), compiled with BPF support
* A recent libc++ or stdc++ library, supporting C++17
* CMake >= 3.16.2. A pre-built binary can be downloaded from the [CMake's download page](https://cmake.org/download/).
* Linux kernel >= 4.18 (Ubuntu 18.10)

Please note that LLVM itself must be compiled with libc++ when enabling the `EBPF_COMMON_ENABLE_LIBCPP` option, since ebfpub will directly link against the LLVM libraries.

### Dependencies
* [ebpf-common](https://github.com/trailofbits/ebpf-common)

### Building with the osquery toolchain (preferred)

**This should work fine on any recent Linux distribution. The binaries generated with this toolchain are portable and can be deployed on any distro >= CentOS 6/Ubuntu 16.04**

As root, download and install the osquery-toolchain:

```bash
cd /tmp
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz 
tar -xf /tmp/ebpfpub/build/osquery-toolchain-1.1.0-x86_64.tar.xz -C /opt
```

1. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfpub`
2. In case the `--recursive` flag was not provided, run `git submodule update --init --recursive`
3. Enter the source folder: `cd ebpfpub`
4. Create the build folder: `mkdir build && cd build`
5. Configure the project: `cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DEBPF_COMMON_TOOLCHAIN_PATH:PATH=/opt/osquery-toolchain -DEBPFPUB_ENABLE_INSTALL:BOOL=true -DEBPFPUB_BUILD_EXAMPLES:BOOL=true -DEBPF_COMMON_ENABLE_TESTS:BOOL=true ..`
6. Build the project: `cmake --build . -j $(($(nproc) + 1))`
7. Run the tests: `cmake --build . --target run-ebpf-common-tests`

### Building with the system toolchain

**Note that this will fail unless clang and the C++ library both support C++17**. Recent distributions should be compatible (tested on Arch Linux, Ubuntu 19.10).

1. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfpub`
2. In case the `--recursive` flag was not provided, run `git submodule update --init --recursive`
3. Enter the source folder: `cd ebpfpub`
4. Create the build folder: `mkdir build && cd build`
5. Configure the project: `cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DCMAKE_C_COMPILER:STRING=clang -DCMAKE_CXX_COMPILER=clang++ -DEBPFPUB_ENABLE_INSTALL:BOOL=true -DEBPFPUB_BUILD_EXAMPLES:BOOL=true -DEBPF_COMMON_ENABLE_TESTS:BOOL=true ..`
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
