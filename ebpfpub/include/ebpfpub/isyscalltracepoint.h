/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

#include <ebpfpub/ibufferstorage.h>
#include <ebpfpub/iperfeventarray.h>

namespace ebpfpub {
class ISyscallTracepoint {
public:
  struct Event final {
    struct Header final {
      std::uint64_t timestamp{0U};

      pid_t parent_process_id{0U}; // todo
      pid_t thread_id{0};
      pid_t process_id{0};

      uid_t user_id{0};
      gid_t group_id{0};

      std::uint64_t exit_code{0U};
      bool probe_error{false};
    };

    struct Integer final {
      enum class Type { Int8, Int16, Int32, Int64 };

      Type type;
      bool is_signed{false};
      std::uint64_t value{0U};
    };

    using Variant =
        std::variant<std::string, std::vector<std::uint8_t>, Integer>;

    using OptionalVariant = std::optional<Variant>;

    using FieldMap = std::unordered_map<std::string, OptionalVariant>;

    std::string syscall_name;
    Header header;
    FieldMap field_map;
  };

  using EventList = std::vector<Event>;

  using Ref = std::unique_ptr<ISyscallTracepoint>;

  static StringErrorOr<Ref> create(const std::string &syscall_name,
                                   IBufferStorage::Ref buffer_storage,
                                   IPerfEventArray::Ref perf_event_array,
                                   std::size_t event_map_size);

  ISyscallTracepoint() = default;
  virtual ~ISyscallTracepoint() = default;

  virtual const std::string &syscallName() const = 0;
  virtual const std::string &serializerName() const = 0;

  virtual StringErrorOr<std::string> generateIR() const = 0;
  virtual std::uint32_t eventIdentifier() const = 0;

  ISyscallTracepoint(const ISyscallTracepoint &) = delete;
  ISyscallTracepoint &operator=(const ISyscallTracepoint &) = delete;
};
} // namespace ebpfpub
