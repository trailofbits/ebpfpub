#pragma once
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include <ebpfpub/error.h>

namespace ebpfpub {
struct UserSettings final {
  bool verbose_flag{false};
  std::vector<std::string> tracepoint_list;
  std::size_t buffer_size{4096};
  std::size_t buffer_count{4096};
  std::size_t perf_event_array_size{5U};
  std::size_t event_map_size{1024};
};

StringErrorOr<UserSettings> parseUserSettings(int argc, char *argv[]);
} // namespace ebpfpub
