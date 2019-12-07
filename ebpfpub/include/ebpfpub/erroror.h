#pragma once

#include <stdexcept>
#include <variant>

namespace ebpfpub {
template <typename ValueType, typename ErrorType> class ErrorOr final {
  std::variant<ErrorType, ValueType> value_variant;
  mutable bool status_checked{false};

public:
  bool succeeded() const {
    status_checked = true;
    return std::holds_alternative<ValueType>(value_variant);
  }

  const ErrorType &error() const {
    assertChecked();
    assertFailed();

    return std::get<ErrorType>(value_variant);
  }

  const ValueType &value() const {
    assertChecked();
    assertSucceeded();

    return std::get<ValueType>(value_variant);
  }

  ValueType takeValue() {
    assertChecked();
    assertSucceeded();

    auto value = std::move(std::get<ValueType>(value_variant));
    value_variant = ErrorType();

    return value;
  }

  const ValueType *operator->() const { return &value(); }

  ErrorOr() {
    value_variant = ErrorType();
    status_checked = true;
  }

  ErrorOr(const ValueType &value) { value_variant = value; }
  ErrorOr(ValueType &&value) { value_variant = std::move(value); }

  ErrorOr(const ErrorType &error) { value_variant = error; }
  ErrorOr(ErrorType &&error) { value_variant = std::move(error); }

  ErrorOr(ErrorOr &&other) noexcept {
    value_variant = std::exchange(other.value_variant, ErrorType());
    status_checked = std::exchange(other.status_checked, true);
  }

  ErrorOr &operator=(ErrorOr &&other) noexcept {
    if (this != &other) {
      value_variant = std::exchange(other.value_variant, ErrorType());
      status_checked = std::exchange(other.status_checked, true);
    }

    return *this;
  }

  ~ErrorOr() = default;

  ErrorOr(const ErrorOr &) = delete;
  ErrorOr &operator=(const ErrorOr &) = delete;

private:
  void assertChecked() const {
    if (status_checked) {
      return;
    }

    throw std::logic_error("The operation was not checked for success");
  }

  void assertSucceeded() const {
    if (std::holds_alternative<ValueType>(value_variant)) {
      return;
    }

    throw std::logic_error("The operation has not succeeded");
  }

  void assertFailed() const {
    if (std::holds_alternative<ErrorType>(value_variant)) {
      return;
    }

    throw std::logic_error("The operation has not failed");
  }
};
} // namespace ebpfpub
