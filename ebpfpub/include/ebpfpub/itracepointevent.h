#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include <ebpfpub/error.h>

namespace ebpfpub {
class ITracepointEvent {
public:
  using Ref = std::shared_ptr<ITracepointEvent>;

  struct StructureField final {
    std::string type;
    std::string name;
    std::size_t offset{0U};
    std::size_t size{0U};
    bool is_signed{false};
  };

  using Structure = std::vector<StructureField>;

  enum class PathType { Root, EnableSwitch, Format, EventIdentifier };
  using PathMap = std::unordered_map<PathType, std::string>;

  static StringErrorOr<Ref> create(const std::string &category,
                                   const std::string &name);

  ITracepointEvent() = default;
  virtual ~ITracepointEvent() = default;

  virtual const std::string &category() const = 0;
  virtual const std::string &name() const = 0;

  virtual StringErrorOr<std::string> path(const PathType &path_type) const = 0;
  virtual std::uint32_t eventIdentifier() const = 0;

  virtual const Structure &structure() const = 0;

  virtual bool enable() = 0;
  virtual bool disable() = 0;

  ITracepointEvent(const ITracepointEvent &) = delete;
  ITracepointEvent &operator=(const ITracepointEvent &) = delete;
};
} // namespace ebpfpub
