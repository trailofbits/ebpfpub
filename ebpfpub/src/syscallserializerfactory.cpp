/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "syscallserializerfactory.h"

#include <unordered_map>

#include <ebpfpub/serializers/connectsyscallserializer.h>
#include <ebpfpub/serializers/execvesyscallserializer.h>
#include <ebpfpub/serializers/genericsyscallserializer.h>

namespace tob::ebpfpub {
namespace {
std::unordered_map<std::string, IFunctionSerializer::Factory>
    kSyscallSerializerFactory;

template <typename Serializer>
StringErrorOr<IFunctionSerializer::Ref>
serializerFactory(IBufferStorage &buffer_storage) {

  try {
    return IFunctionSerializer::Ref(new Serializer(buffer_storage));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

template <typename Serializer>
SuccessOrStringError registerSerializerFactory() {
  const auto &name = Serializer::name;

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

  success_exp = registerSerializerFactory<ExecveSyscallSerializer>();
  if (success_exp.failed()) {
    return success_exp.error();
  }

  return {};
}

StringErrorOr<IFunctionSerializer::Ref>
createSerializer(std::string name, IBufferStorage &buffer_storage) {
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
  return factory(buffer_storage);
}
} // namespace tob::ebpfpub
