#pragma once

#include "bpfmap.h"

#include <sys/sysinfo.h>

namespace ebpfpub {
template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
class TypedBPFMap final {
public:
  // clang-format off
  static_assert(
    std::is_standard_layout<ValueType>::value && std::is_trivial<ValueType>::value,
    "The value type must be a POD"
  );
  // clang-format on

  using BaseBPFMapType = BPFMap<map_type, KeyType>;
  using Ref = std::unique_ptr<TypedBPFMap>;

  static StringErrorOr<Ref> create(std::size_t entry_count);
  virtual ~TypedBPFMap() = default;

  int fd() const;

  BPFMapErrorCode set(const KeyType &key, const ValueType &value);
  BPFMapErrorCode get(ValueType &value, const KeyType &key);
  BPFMapErrorCode erase(const KeyType &key);

protected:
  TypedBPFMap(std::size_t entry_count);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
struct TypedBPFMap<map_type, KeyType, ValueType>::PrivateData final {
  typename BaseBPFMapType::Ref bpf_map;
};

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
StringErrorOr<typename TypedBPFMap<map_type, KeyType, ValueType>::Ref>
TypedBPFMap<map_type, KeyType, ValueType>::create(std::size_t entry_count) {

  try {
    return Ref(new TypedBPFMap<map_type, KeyType, ValueType>(entry_count));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
int TypedBPFMap<map_type, KeyType, ValueType>::fd() const {
  return d->bpf_map->fd();
}

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
BPFMapErrorCode
TypedBPFMap<map_type, KeyType, ValueType>::set(const KeyType &key,
                                               const ValueType &value) {

  std::size_t value_size = sizeof(value);

  std::size_t buffer_size = value_size;
  std::size_t slot_count{1U};

  if (map_type == BPF_MAP_TYPE_PERCPU_HASH ||
      map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
      map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {

    slot_count = static_cast<std::size_t>(get_nprocs_conf());
    buffer_size *= slot_count;
  }

  std::vector<std::uint8_t> buffer(buffer_size);

  for (auto i = 0U; i < slot_count; ++i) {
    auto buffer_ptr = buffer.data() + (i * value_size);
    std::memcpy(buffer_ptr, &value, value_size);
  }

  return d->bpf_map->set(key, buffer);
}

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
BPFMapErrorCode
TypedBPFMap<map_type, KeyType, ValueType>::get(ValueType &value,
                                               const KeyType &key) {

  std::vector<std::uint8_t> buffer;
  auto err = d->bpf_map->get(buffer, key);
  if (err.value() != BPFMapErrorCode::Value::Success) {
    return err;
  }

  std::memcpy(&value, buffer.data(), buffer.size());
  return BPFMapErrorCode::Value::Success;
}

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
BPFMapErrorCode
TypedBPFMap<map_type, KeyType, ValueType>::erase(const KeyType &key) {
  return d->bpf_map->erase(key);
}

template <enum bpf_map_type map_type, typename KeyType, typename ValueType>
TypedBPFMap<map_type, KeyType, ValueType>::TypedBPFMap(std::size_t entry_count)
    : d(new PrivateData) {

  auto bpf_map_exp = BaseBPFMapType::create(sizeof(ValueType), entry_count);

  if (!bpf_map_exp.succeeded()) {
    throw bpf_map_exp.error();
  }

  d->bpf_map = bpf_map_exp.takeValue();
}
} // namespace ebpfpub
