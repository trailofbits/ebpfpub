#include "uniquefd.h"

#include <unistd.h>

namespace ebpfpub {
void FdDeleter::operator()(FdDeleter::Reference fd) const {
  if (fd == -1) {
    return;
  }

  close(fd);
}
} // namespace ebpfpub
