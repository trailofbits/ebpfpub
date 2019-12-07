#include "utils.h"

#include <stdexcept>

#include <sys/resource.h>

namespace ebpfpub {
void setRlimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto error = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (error != 0) {
    throw std::runtime_error("Failed to set RLIMIT_MEMLOCK");
  }
}
} // namespace ebpfpub
