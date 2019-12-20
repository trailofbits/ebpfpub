/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "syscallserializerfactory.h"
#include "connectsyscallserializer.h"
#include "genericsyscallserializer.h"

#include <unordered_map>

namespace tob::ebpfpub {
namespace {
std::unordered_map<std::string, ISyscallSerializer::Factory>
    kSyscallSerializerFactory;

template <typename Serializer>
StringErrorOr<ISyscallSerializer::Ref> serializerFactory() {
  try {
    return ISyscallSerializer::Ref(new Serializer());

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

template <typename Serializer>
SuccessOrStringError registerSerializerFactory() {
  std::string name;

  {
    Serializer serializer;
    name = serializer.name();
  }

  if (kSyscallSerializerFactory.find(name) != kSyscallSerializerFactory.end()) {
    return StringError::create(
        "The following serializer has been already registered: " + name);
  }

  kSyscallSerializerFactory.insert({name, serializerFactory<Serializer>});

  return {};
}
} // namespace

SuccessOrStringError initializeSerializerFactory() {
  auto success_exp = registerSerializerFactory<GenericSyscallSerializer>();
  if (success_exp.failed()) {
    return success_exp.error();
  }

  success_exp = registerSerializerFactory<ConnectSyscallSerializer>();
  if (success_exp.failed()) {
    return success_exp.error();
  }

  return {};
}

StringErrorOr<ISyscallSerializer::Ref> createSerializer(std::string name) {
  auto factory_it = kSyscallSerializerFactory.find(name);
  if (factory_it == kSyscallSerializerFactory.end()) {
    name = "generic";
  }

  factory_it = kSyscallSerializerFactory.find(name);
  if (factory_it == kSyscallSerializerFactory.end()) {
    return StringError::create("No serializer named '" + name +
                               "' was found and the fallback one has failed");
  }

  const auto &factory = factory_it->second;
  return factory();
}
} // namespace tob::ebpfpub
