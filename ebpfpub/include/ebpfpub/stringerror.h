#pragma once

#include <ebpfpub/erroror.h>

namespace ebpfpub {
class StringError final {
public:
  static StringError create(const std::string &message);
  StringError();

  const std::string &message() const;

protected:
  StringError(const std::string &message);

private:
  std::string message_;
};
} // namespace ebpfpub
