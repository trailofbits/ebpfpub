#include <ebpfpub/error.h>

namespace ebpfpub {
StringError StringError::create(const std::string &message) {
  return StringError(message);
}

StringError::StringError() : message_("Uninitialized error mesage") {}

const std::string &StringError::message() const { return message_; }

StringError::StringError(const std::string &message) : message_(message) {}
} // namespace ebpfpub
