/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <optional>
#include <stdexcept>

namespace ebpfpub {
template <typename ErrorType> class SuccessOr final {
  std::optional<ErrorType> optional_error;
  mutable bool status_checked{false};

public:
  bool failed() const {
    status_checked = true;
    return optional_error.has_value();
  }

  const ErrorType &error() const {
    if (!status_checked) {
      throw std::logic_error("The operation was not checked for failure");
    }

    if (!optional_error.has_value()) {
      throw std::logic_error("The operation has not failed");
    }

    return optional_error.value();
  }

  SuccessOr() = default;

  SuccessOr(const ErrorType &error) { optional_error = error; }

  SuccessOr(SuccessOr &&other) noexcept {
    optional_error =
        std::exchange(other.optional_error, std::optional<ErrorType>());

    status_checked = std::exchange(other.status_checked, true);
  }

  SuccessOr &operator=(SuccessOr &&other) noexcept {
    if (this != &other) {
      optional_error =
          std::exchange(other.optional_error, std::optional<ErrorType>());

      status_checked = std::exchange(other.status_checked, true);
    }

    return *this;
  }

  ~SuccessOr() = default;

  SuccessOr(const SuccessOr &) = delete;
  SuccessOr &operator=(const SuccessOr &) = delete;
};
} // namespace ebpfpub
