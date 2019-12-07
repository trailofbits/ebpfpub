#pragma once

#include <ebpfpub/errorcode.h>
#include <ebpfpub/erroror.h>
#include <ebpfpub/stringerror.h>
#include <ebpfpub/successor.h>

namespace ebpfpub {
template <typename ValueType>
using StringErrorOr = ErrorOr<ValueType, StringError>;

using SuccessOrStringError = SuccessOr<StringError>;
} // namespace ebpfpub
