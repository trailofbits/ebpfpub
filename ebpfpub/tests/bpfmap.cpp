#include "bpfmap.h"

#include <cstdint>

#include <catch2/catch.hpp>

namespace ebpfpub {
namespace {
using TestBPFHashMap = BPFMap<BPF_MAP_TYPE_HASH, std::uint32_t>;

const std::size_t kHashMapSize{32U};
const std::size_t kValueSize{4U};

TestBPFHashMap::Ref bpf_hash_map;
const std::vector<std::uint8_t> kTestValue(kValueSize, 0xFFU);
} // namespace

TEST_CASE("Setting values", "[BPFMap]") {
  if (!bpf_hash_map) {
    auto bpf_hash_map_exp = TestBPFHashMap::create(kValueSize, kHashMapSize);
    REQUIRE(bpf_hash_map_exp.succeeded());

    bpf_hash_map = bpf_hash_map_exp.takeValue();
  }

  SECTION("Setting values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      auto err = bpf_hash_map->set(i, kTestValue);
      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      REQUIRE(err.succeeded());
    }
  }

  SECTION("Retrieving existing values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      std::vector<std::uint8_t> value;
      auto err = bpf_hash_map->get(value, i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      REQUIRE(err.succeeded());

      REQUIRE(value == kTestValue);
    }
  }

  SECTION("Removing existing values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      auto err = bpf_hash_map->erase(i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::Success);
      REQUIRE(err.succeeded());
    }
  }

  SECTION("Retrieving inexisting values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      std::vector<std::uint8_t> value;
      auto err = bpf_hash_map->get(value, i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::NotFound);
      REQUIRE(err.succeeded());

      REQUIRE(value.size() == kValueSize);
    }
  }

  SECTION("Removing inexisting values") {
    for (std::uint32_t i = 0; i < kHashMapSize; ++i) {
      auto err = bpf_hash_map->erase(i);

      REQUIRE(err.value() == BPFMapErrorCode::Value::NotFound);
      REQUIRE(err.succeeded());
    }
  }
}
} // namespace ebpfpub
