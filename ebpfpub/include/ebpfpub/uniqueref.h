#pragma once

#include <utility>

namespace ebpfpub {
template <typename ReferenceDeleter> class UniqueRef final {
public:
  using Reference = typename ReferenceDeleter::Reference;

  constexpr UniqueRef() noexcept = default;

  explicit UniqueRef(Reference reference) noexcept : ref(reference){};

  UniqueRef(UniqueRef &&other) { *this = std::move(other); }

  UniqueRef(const UniqueRef &) = delete;

  ~UniqueRef() { releaseReference(); };

  UniqueRef &operator=(const UniqueRef &) = delete;

  UniqueRef &operator=(UniqueRef &&other) {
    if (this != &other) {
      releaseReference();

      ref = std::move(other.ref);
      other.ref = ReferenceDeleter::kNullReference;
    }

    return *this;
  }

  UniqueRef &operator=(Reference new_ref) {
    releaseReference();
    reset(new_ref);
  }

  Reference release() noexcept {
    auto ref_ = std::move(ref);
    ref = ReferenceDeleter::kNullReference;

    return ref_;
  }

  void reset(Reference new_ref = ReferenceDeleter::kNullReference) noexcept {
    releaseReference();
    ref = new_ref;
  }

  void swap(UniqueRef &other) noexcept { std::swap(ref, other.ref); }

  Reference get() const noexcept { return ref; }

  explicit operator bool() const noexcept {
    return ref != ReferenceDeleter::kNullReference;
  }

  Reference operator*() const noexcept { return *get(); }

  Reference operator->() const noexcept { return get(); }

private:
  Reference ref{ReferenceDeleter::kNullReference};

  void releaseReference() {
    static const ReferenceDeleter kReferenceDeleter;
    kReferenceDeleter(ref);

    ref = ReferenceDeleter::kNullReference;
  }
};
} // namespace ebpfpub
