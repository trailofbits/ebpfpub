#include <memory>

#include <catch2/catch.hpp>

#include <ebpfpub/erroror.h>

namespace ebpfpub {
namespace {
std::size_t dealloc_count{0U};

struct TestDeleter final {
  void operator()(void *ptr) const {
    if (ptr != nullptr) {
      ++dealloc_count;
    }
  }
};

using TestUniquePtr = std::unique_ptr<void, TestDeleter>;
using TestErrorOr = ErrorOr<TestUniquePtr, std::string>;
} // namespace

TEST_CASE("Value lifetime", "[ErrorOr]") {
  void *kDummyPointer{reinterpret_cast<void *>(1)};

  SECTION("Must not be copyable") {
    REQUIRE(std::is_copy_constructible<TestErrorOr>::value == 0);
    REQUIRE(std::is_trivially_copy_constructible<TestErrorOr>::value == 0);
    REQUIRE(std::is_nothrow_copy_constructible<TestErrorOr>::value == 0);

    REQUIRE(std::is_copy_assignable<TestErrorOr>::value == 0);
    REQUIRE(std::is_trivially_copy_assignable<TestErrorOr>::value == 0);
    REQUIRE(std::is_nothrow_copy_assignable<TestErrorOr>::value == 0);
  }

  SECTION("Setting and getting the value object") {
    {
      dealloc_count = 0U;
      TestUniquePtr test_unique_ptr;

      REQUIRE(dealloc_count == 0U);
      test_unique_ptr.reset(kDummyPointer);
    }

    REQUIRE(dealloc_count == 1U);

    dealloc_count = 0U;
    TestUniquePtr non_copyable_value;
    non_copyable_value.reset(kDummyPointer);
    REQUIRE(dealloc_count == 0U);

    TestErrorOr test_exp;
    test_exp = std::move(non_copyable_value);
    REQUIRE(dealloc_count == 0U);

    REQUIRE(test_exp.succeeded());

    {
      auto restored_value = test_exp.takeValue();
      REQUIRE(dealloc_count == 0U);

      REQUIRE(restored_value.get() == kDummyPointer);
    }

    REQUIRE(dealloc_count == 1U);
  }

  SECTION("Moving an ErrorOr with a valid value") {
    dealloc_count = 0U;

    TestErrorOr original;

    {
      TestUniquePtr test_unique_ptr;

      REQUIRE(dealloc_count == 0U);
      test_unique_ptr.reset(kDummyPointer);

      original = std::move(test_unique_ptr);
      REQUIRE(dealloc_count == 0U);
    }

    auto L_moveObject = [](TestErrorOr original) -> TestErrorOr {
      TestErrorOr moved1 = std::move(original);
      original = {};

      TestErrorOr moved2(std::move(moved1));
      moved1 = {};

      return moved2;
    };

    auto moved = L_moveObject(std::move(original));
    REQUIRE(moved.succeeded());

    auto value = moved.takeValue();
    REQUIRE(dealloc_count == 0U);
    REQUIRE(value.get() == kDummyPointer);

    value.reset();
    REQUIRE(dealloc_count == 1U);
  }
}
} // namespace ebpfpub
