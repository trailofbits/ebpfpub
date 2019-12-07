#pragma once

#include "isyscallserializer.h"

#include <ebpfpub/error.h>

namespace ebpfpub {
SuccessOrStringError initializeSerializerFactory();

StringErrorOr<ISyscallSerializer::Ref> createSerializer(std::string name);
} // namespace ebpfpub
