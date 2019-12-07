#pragma once

namespace ebpfpub {
template <typename Result, typename Result::ErrorCode DefaultErrorValue>
class ErrorCode final {
public:
  using Value = typename Result::ErrorCode;

  ErrorCode() = default;
  ErrorCode(typename Result::ErrorCode value) : error_value(value) {}

  typename Result::ErrorCode value() const { return error_value; }

  bool succeeded() const { return Result()(error_value); }

private:
  typename Result::ErrorCode error_value{DefaultErrorValue};
};
} // namespace ebpfpub
