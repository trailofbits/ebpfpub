/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/error.h>

#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

#include <asm/unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <sys/sysinfo.h>
#include <unistd.h>

namespace ebpfpub {
struct BPFMapResult final {
  enum class ErrorCode {
    Success,
    NotFound,

    InvalidValueSize,
    InvalidProcessorIndex,
    Error
  };

  bool operator()(ErrorCode error) const {
    return error == ErrorCode::Success || error == ErrorCode::NotFound;
  }
};

using BPFMapErrorCode = ErrorCode<BPFMapResult, BPFMapResult::ErrorCode::Error>;

template <enum bpf_map_type map_type, typename KeyType> class BPFMap final {
  // clang-format off
  static_assert(
    map_type == BPF_MAP_TYPE_HASH ||
    map_type == BPF_MAP_TYPE_ARRAY ||
    map_type == BPF_MAP_TYPE_PROG_ARRAY ||
    map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
    map_type == BPF_MAP_TYPE_PERCPU_HASH ||
    map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
    map_type == BPF_MAP_TYPE_STACK_TRACE ||
    map_type == BPF_MAP_TYPE_CGROUP_ARRAY ||
    map_type == BPF_MAP_TYPE_LRU_HASH ||
    map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
    map_type == BPF_MAP_TYPE_LPM_TRIE ||
    map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
    map_type == BPF_MAP_TYPE_HASH_OF_MAPS ||
    map_type == BPF_MAP_TYPE_DEVMAP ||
    map_type == BPF_MAP_TYPE_SOCKMAP ||
    map_type == BPF_MAP_TYPE_CPUMAP,

    "Invalid BPF map type"
  );
  // clang-format on

public:
  enum class ErrorType {
    Unknown,
    MemoryAllocationFailure,
    MapCreationFailure,
    UpdateElementFailure,
    LookupElementFailure,
    EraseElementFailure,
    InvalidValueSize,
    NotFound
  };

  static const std::unordered_map<ErrorType, std::string> kStringErrorType;

  using Ref = std::unique_ptr<BPFMap>;

  static StringErrorOr<Ref> create(std::size_t value_size,
                                   std::size_t entry_count);

  ~BPFMap();

  int fd() const;
  std::size_t valueSize() const;

  BPFMapErrorCode set(const KeyType &key,
                      const std::vector<std::uint8_t> &value);

  BPFMapErrorCode set(const KeyType &key, const std::uint8_t *value);

  BPFMapErrorCode get(std::vector<std::uint8_t> &value, const KeyType &key);
  BPFMapErrorCode get(std::uint8_t *value, const KeyType &key);

  BPFMapErrorCode erase(const KeyType &key);

protected:
  BPFMap(std::size_t value_size, std::size_t entry_count);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

template <enum bpf_map_type map_type, typename KeyType>
struct BPFMap<map_type, KeyType>::PrivateData final {
  union bpf_attr map_attr {};
  std::size_t value_size{0U};
  int fd{-1};
};

template <enum bpf_map_type map_type, typename KeyType>
StringErrorOr<typename BPFMap<map_type, KeyType>::Ref>
BPFMap<map_type, KeyType>::create(std::size_t value_size,
                                  std::size_t entry_count) {

  try {
    return Ref(new BPFMap<map_type, KeyType>(value_size, entry_count));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMap<map_type, KeyType>::~BPFMap() {
  close(d->fd);
}

template <enum bpf_map_type map_type, typename KeyType>
int BPFMap<map_type, KeyType>::fd() const {
  return d->fd;
}

template <enum bpf_map_type map_type, typename KeyType>
std::size_t BPFMap<map_type, KeyType>::valueSize() const {
  return d->value_size;
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMapErrorCode
BPFMap<map_type, KeyType>::set(const KeyType &key,
                               const std::vector<std::uint8_t> &value) {

  auto processor_count = static_cast<std::size_t>(get_nprocs_conf());

  auto value_size = d->value_size;
  if (map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
      map_type == BPF_MAP_TYPE_PERCPU_HASH ||
      map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {

    value_size *= processor_count;
  }

  if (value.size() != value_size) {
    return BPFMapErrorCode::Value::InvalidValueSize;
  }

  return set(key, value.data());
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMapErrorCode BPFMap<map_type, KeyType>::set(const KeyType &key,
                                               const std::uint8_t *value) {

  union bpf_attr attr = {};
  memset(&attr, 0, sizeof(union bpf_attr));

  attr.map_fd = static_cast<__u32>(d->fd);
  attr.key = reinterpret_cast<__u64>(&key);
  attr.value = reinterpret_cast<__u64>(value);
  attr.flags = BPF_ANY;

  auto err =
      ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr));

  if (err < 0) {
    return BPFMapErrorCode::Value::Error;
  }

  return BPFMapErrorCode::Value::Success;
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMapErrorCode BPFMap<map_type, KeyType>::get(std::vector<std::uint8_t> &value,
                                               const KeyType &key) {

  auto processor_count = static_cast<std::size_t>(get_nprocs_conf());

  auto value_size = d->value_size;
  if (map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
      map_type == BPF_MAP_TYPE_PERCPU_HASH ||
      map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {

    value_size *= processor_count;
  }

  value.resize(value_size);
  return get(value.data(), key);
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMapErrorCode BPFMap<map_type, KeyType>::get(std::uint8_t *value,
                                               const KeyType &key) {
  union bpf_attr attr = {};
  memset(&attr, 0, sizeof(union bpf_attr));

  attr.map_fd = static_cast<__u32>(d->fd);
  attr.key = reinterpret_cast<__u64>(&key);
  attr.value = reinterpret_cast<__u64>(value);

  auto err =
      ::syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(union bpf_attr));

  if (err < 0) {
    BPFMapErrorCode exit_code;
    if (errno == ENOENT) {
      exit_code = BPFMapErrorCode::Value::NotFound;
    } else {
      exit_code = BPFMapErrorCode::Value::Error;
    }

    return exit_code;
  }

  return BPFMapErrorCode::Value::Success;
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMapErrorCode BPFMap<map_type, KeyType>::erase(const KeyType &key) {

  union bpf_attr attr = {};
  memset(&attr, 0, sizeof(union bpf_attr));

  attr.map_fd = static_cast<__u32>(d->fd);
  attr.key = reinterpret_cast<__u64>(&key);

  auto err =
      ::syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(union bpf_attr));

  if (err < 0) {
    BPFMapErrorCode exit_code;
    if (errno == ENOENT) {
      exit_code = BPFMapErrorCode::Value::NotFound;
    } else {
      exit_code = BPFMapErrorCode::Value::Error;
    }

    return exit_code;
  }

  return BPFMapErrorCode::Value::Success;
}

template <enum bpf_map_type map_type, typename KeyType>
BPFMap<map_type, KeyType>::BPFMap(std::size_t value_size,
                                  std::size_t entry_count)
    : d(new PrivateData) {
  d->value_size = value_size;

  memset(&d->map_attr, 0, sizeof(union bpf_attr));
  d->map_attr.map_type = map_type;
  d->map_attr.key_size = sizeof(KeyType);
  d->map_attr.value_size = static_cast<__u32>(d->value_size);
  d->map_attr.max_entries = static_cast<__u32>(entry_count);

  auto fd =
      ::syscall(__NR_bpf, BPF_MAP_CREATE, &d->map_attr, sizeof(union bpf_attr));

  if (fd < 0) {
    throw StringError::create("Failed to create the map");
  }

  d->fd = static_cast<int>(fd);
}
} // namespace ebpfpub
