#include "perfeventarray.h"
#include "typedbpfmap.h"

#include <cmath>
#include <cstddef>
#include <iostream>
#include <vector>

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

namespace ebpfpub {
namespace {
using PerfEventArrayMap =
    TypedBPFMap<BPF_MAP_TYPE_PERF_EVENT_ARRAY, std::uint32_t, int>;

static const auto kPerfDataTailOffset =
    offsetof(struct perf_event_mmap_page, data_tail);

static const auto kPerfDataSizeOffset =
    offsetof(struct perf_event_mmap_page, data_size);

static const auto kPerfDataOffsetOffset =
    offsetof(struct perf_event_mmap_page, data_offset);

static const auto kPerfDataHeadOffset =
    offsetof(struct perf_event_mmap_page, data_head);
} // namespace

struct PerfEventArray::PrivateData final {
  PerfEventArrayMap::Ref perf_event_array_map;

  std::size_t single_bpf_output_size{};
  std::size_t processor_count{};

  std::unordered_map<std::size_t, BPFOutput> bpf_output_list;
  std::vector<struct pollfd> bpf_output_list_pollfd;
};

PerfEventArray::~PerfEventArray() {}

std::size_t PerfEventArray::memoryUsage() const {
  return d->processor_count * d->single_bpf_output_size;
}

int PerfEventArray::fd() const { return d->perf_event_array_map->fd(); }

bool PerfEventArray::read(std::vector<std::uint8_t> &buffer,
                          const std::chrono::milliseconds &timeout) {
  buffer = {};

  auto error =
      ::poll(d->bpf_output_list_pollfd.data(), d->bpf_output_list_pollfd.size(),
             static_cast<int>(timeout.count()));

  if (error < 0) {
    if (errno == EINTR) {
      return true;
    }

    return false;

  } else if (error == 0) {
    return true;
  }

  for (auto bpf_output_index = 0U;
       bpf_output_index < d->bpf_output_list_pollfd.size();
       ++bpf_output_index) {

    auto &bpf_output_pollfd = d->bpf_output_list_pollfd.at(bpf_output_index);
    if ((bpf_output_pollfd.revents & POLLIN) == 0) {
      continue;
    }

    bpf_output_pollfd.revents = 0;

    auto perf_buffer_list = readPerfMemory(bpf_output_index);
    if (perf_buffer_list.empty()) {
      continue;
    }

    for (const auto &perf_buffer : perf_buffer_list) {
      if (perf_buffer.size() < sizeof(struct perf_event_header)) {
        std::cerr << "Not enough data in the perf buffer\n";
        continue;
      }

      struct perf_event_header event_header;
      std::memcpy(&event_header, perf_buffer.data(), sizeof(event_header));

      if (event_header.type == PERF_RECORD_LOST) {
        std::cerr << "One or more records have been lost\n";
        continue;
      }

      if (sizeof(struct perf_event_header) + 4U > perf_buffer.size()) {
        std::cerr << "Not enough data in the perf buffer\n";
        continue;
      }

      auto perf_record_size_ptr = perf_buffer.data() + sizeof(event_header);

      std::uint32_t perf_record_size;
      std::memcpy(&perf_record_size, perf_record_size_ptr,
                  sizeof(perf_record_size));

      perf_record_size -= 4U;

      if (perf_record_size > perf_buffer.size() - sizeof(event_header)) {
        std::cerr << "Not enough data in the perf buffer\n";
        continue;
      }

      auto perf_record_data_ptr = perf_record_size_ptr + sizeof(std::uint32_t);

      buffer.insert(buffer.end(), perf_record_data_ptr,
                    perf_record_data_ptr + perf_record_size);
    }
  }

  return true;
}

PerfEventArray::PerfEventArray(std::size_t per_bpf_output_page_exponent)
    : d(new PrivateData) {

  auto page_count =
      static_cast<std::size_t>(1 + std::pow(2, per_bpf_output_page_exponent));

  d->single_bpf_output_size =
      static_cast<std::size_t>(getpagesize()) * page_count;

  auto perf_event_array_map_exp = PerfEventArrayMap::create(128U);
  if (!perf_event_array_map_exp.succeeded()) {
    throw perf_event_array_map_exp.error();
  }

  d->perf_event_array_map = perf_event_array_map_exp.takeValue();

  d->processor_count = static_cast<std::size_t>(get_nprocs_conf());

  for (auto i = 0U; i < d->processor_count; ++i) {
    auto bpf_output_exp = createPerfBPFOutput(i, d->single_bpf_output_size);

    if (!bpf_output_exp.succeeded()) {
      throw bpf_output_exp.error();
    }

    auto bpf_output = bpf_output_exp.takeValue();

    auto err = d->perf_event_array_map->set(i, bpf_output.fd());
    if (!err.succeeded()) {
      throw StringError::create("Failed to populate the perf event array map");
    }

    d->bpf_output_list.insert({i, std::move(bpf_output)});
  }

  // Make sure we populate the poll_fd vector in the correct order
  for (auto i = 0U; i < d->bpf_output_list.size(); ++i) {
    const auto &bpf_output = d->bpf_output_list.at(i);

    struct pollfd poll_fd = {};
    poll_fd.fd = bpf_output.fd();
    poll_fd.events = POLLIN;

    d->bpf_output_list_pollfd.push_back(std::move(poll_fd));
  }
}

StringErrorOr<BPFOutput>
PerfEventArray::createPerfBPFOutput(std::size_t processor_index,
                                    std::size_t bpf_output_size) {

  static const int kNullPid{-1};
  static const int kNullGroupFd{-1};
  static const int kNullFlags{0};

  UniqueFd output_fd;

  {
    struct perf_event_attr attr {};
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_BPF_OUTPUT;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.wakeup_events = 1;
    attr.disabled = 1;

    auto perf_event_fd = ::syscall(__NR_perf_event_open, &attr, kNullPid,
                                   processor_index, kNullGroupFd, kNullFlags);

    if (perf_event_fd == -1) {
      return StringError::create("Failed to create the perf BPF output");
    }

    output_fd.reset(static_cast<int>(perf_event_fd));
  }

  auto output_memory_exp = UniqueMappedMemory::create(
      nullptr, bpf_output_size, PROT_READ | PROT_WRITE, MAP_SHARED,
      output_fd.get(), 0);

  if (!output_memory_exp.succeeded()) {
    return output_memory_exp.error();
  }

  auto output_memory = output_memory_exp.takeValue();

  if (ioctl(output_fd.get(), PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return StringError::create("Failed to enable the perf BPF output");
  }

  return BPFOutput(std::move(output_fd), std::move(output_memory));
}

PerfEventArray::PerfBufferList
PerfEventArray::readPerfMemory(std::size_t bpf_output_index) {

  PerfBufferList buffer_list;

  auto &bpf_output = d->bpf_output_list.at(bpf_output_index);

  auto perf_header_memory = bpf_output.memory();

  std::uint64_t data_size{0U};
  std::memcpy(&data_size, perf_header_memory + kPerfDataSizeOffset,
              sizeof(data_size));

  std::uint64_t data_offset{0U};
  std::memcpy(&data_offset, perf_header_memory + kPerfDataOffsetOffset,
              sizeof(data_offset));

  auto perf_data_memory = perf_header_memory + data_offset;

  for (;;) {
    std::uint64_t data_tail{0U};
    std::memcpy(&data_tail, perf_header_memory + kPerfDataTailOffset,
                sizeof(data_tail));

    std::uint64_t data_head{0U};
    std::memcpy(&data_head, perf_header_memory + kPerfDataHeadOffset,
                sizeof(data_head));

    if (data_tail == data_head) {
      break;
    }

    auto event_data_start = perf_data_memory + (data_tail % data_size);

    struct perf_event_header event_header;
    std::memcpy(&event_header, event_data_start, sizeof(event_header));

    auto event_data_end =
        perf_data_memory + ((data_tail + event_header.size) % data_size);

    auto buffer = std::vector<std::uint8_t>(event_header.size);

    if (event_data_end < event_data_start) {
      auto bytes_until_wrap = static_cast<std::size_t>(
          (perf_data_memory + data_size) - event_data_start);

      std::memcpy(buffer.data(), event_data_start, bytes_until_wrap);
      std::memcpy(buffer.data() + bytes_until_wrap, perf_data_memory,
                  event_header.size - bytes_until_wrap);

    } else {
      std::memcpy(buffer.data(), event_data_start, event_header.size);
    }

    buffer_list.push_back(std::move(buffer));

    data_tail += event_header.size;
    std::memcpy(perf_header_memory + kPerfDataTailOffset, &data_tail,
                sizeof(data_tail));
  }

  return buffer_list;
}

StringErrorOr<IPerfEventArray::Ref>
IPerfEventArray::create(std::size_t per_bpf_output_page_exponent) {
  try {
    return Ref(new PerfEventArray(per_bpf_output_page_exponent));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace ebpfpub
