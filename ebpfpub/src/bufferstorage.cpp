/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "bufferstorage.h"

#include <sys/sysinfo.h>
#include <unistd.h>

#include <tob/ebpf/typedbpfmap.h>

namespace tob::ebpfpub {
namespace {
using BufferMap = ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;

using IndexMap =
    ebpf::TypedBPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t, std::uint32_t>;
} // namespace

struct BufferStorage::PrivateData final {
  std::size_t buffer_size{0U};
  std::size_t buffer_count{0U};

  BufferMap::Ref buffer_map;
  IndexMap::Ref index_map;
};

BufferStorage::~BufferStorage() {}

std::size_t BufferStorage::memoryUsage() const {
  auto processor_count = static_cast<std::size_t>(get_nprocs_conf());
  return processor_count * (bufferSize() * bufferCount());
}

std::size_t BufferStorage::bufferSize() const { return d->buffer_size; }

std::size_t BufferStorage::bufferCount() const { return d->buffer_count; }

int BufferStorage::bufferMap() const { return d->buffer_map->fd(); }

int BufferStorage::indexMap() const { return d->buffer_map->fd(); }

ebpf::BPFMapErrorCode BufferStorage::getBuffer(std::vector<std::uint8_t> &value,
                                               std::uint64_t index) {

  auto key = static_cast<std::uint32_t>(index & 0xFFFFFFFFULL);
  auto processor = static_cast<std::uint32_t>((index >> 48ULL) & 0xFFULL);

  auto processor_count = static_cast<std::size_t>(get_nprocs_conf());
  if (processor >= processor_count) {
    return ebpf::BPFMapErrorCode::Value::InvalidProcessorIndex;
  }

  std::vector<std::uint8_t> buffer;
  auto err = d->buffer_map->get(buffer, key);
  if (!err.succeeded()) {
    return err;
  }

  auto section_ptr = buffer.data() + (processor * d->buffer_size);

  value.resize(d->buffer_size);
  std::memcpy(value.data(), section_ptr, value.size());

  return ebpf::BPFMapErrorCode::Value::Success;
}

BufferStorage::BufferStorage(std::size_t buffer_size, std::size_t buffer_count)
    : d(new PrivateData) {

  d->buffer_size = buffer_size;
  d->buffer_count = buffer_count;

  auto buffer_map_exp = BufferMap::create(buffer_size, buffer_count);

  if (!buffer_map_exp.succeeded()) {
    throw buffer_map_exp.error();
  }

  d->buffer_map = buffer_map_exp.takeValue();

  auto index_map_exp = IndexMap::create(1U);

  if (!index_map_exp.succeeded()) {
    throw index_map_exp.error();
  }

  d->index_map = index_map_exp.takeValue();
}

StringErrorOr<IBufferStorage::Ref>
IBufferStorage::create(std::size_t buffer_size, std::size_t buffer_count) {

  try {
    return Ref(new BufferStorage(buffer_size, buffer_count));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace tob::ebpfpub
