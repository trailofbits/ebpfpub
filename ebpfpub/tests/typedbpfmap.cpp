/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "typedbpfmap.h"

#include <cstdint>

#include <catch2/catch.hpp>

namespace ebpfpub {
namespace {
using TestBPFHashMap =
    TypedBPFMap<BPF_MAP_TYPE_HASH, std::uint32_t, std::uint32_t>;
}

SCENARIO(
    "The TypedBPFMap class can instantiate and manipulate typed BPF hash maps",
    "[TypedBPFMap]") {

  GIVEN("a typed BPF hash map") {
    const std::size_t kHashMapSize{10U};

    auto bpf_hash_map_exp = TestBPFHashMap::create(kHashMapSize);
    REQUIRE(bpf_hash_map_exp.succeeded());

    auto bpf_hash_map = bpf_hash_map_exp.takeValue();

    WHEN("setting new values") {
      for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
        auto err = bpf_hash_map->set(i, i);
        REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      }

      THEN("the same values can be looked up") {
        for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
          std::uint32_t value{0U};

          auto err = bpf_hash_map->get(value, i);
          REQUIRE(err.value() == BPFMapErrorCode::Value::Success);

          CHECK(value == i);
        }
      }
    }

    WHEN("retrieving inexistent values") {
      std::uint32_t value{0U};
      auto err = bpf_hash_map->get(value, 1000U);

      THEN("failure with NotFound is returned along with an empty value") {
        REQUIRE(err.value() == BPFMapErrorCode::Value::NotFound);
      }
    }

    WHEN("removing inexistent values") {
      auto err = bpf_hash_map->erase(1000U);

      THEN("NotFound is returned") {
        REQUIRE(err.value() == BPFMapErrorCode::Value::NotFound);
      }
    }

    WHEN("removing existing values") {
      auto err = bpf_hash_map->set(1U, 1U);
      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);

      err = bpf_hash_map->erase(1U);
      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);

      THEN("the values are no longer present") {
        std::uint32_t value{0U};

        err = bpf_hash_map->get(value, 1U);
        CHECK(err.value() == BPFMapErrorCode::Value::NotFound);
      }
    }
  }
}
} // namespace ebpfpub
