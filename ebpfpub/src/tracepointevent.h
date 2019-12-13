/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <ebpfpub/itracepointevent.h>

namespace ebpfpub {
class TracepointEvent final : public ITracepointEvent {
public:
  virtual ~TracepointEvent() override;

  virtual const std::string &category() const override;
  virtual const std::string &name() const override;

  virtual StringErrorOr<std::string>
  path(const PathType &path_type) const override;

  virtual std::uint32_t eventIdentifier() const override;

  virtual const Structure &structure() const override;

  virtual bool enable() override;
  virtual bool disable() override;

protected:
  TracepointEvent(const std::string &category, const std::string &name);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static PathMap getTracepointPathMap(const std::string &category,
                                      const std::string &name);

  static StringErrorOr<std::string> readFile(const std::string &path);

  static StringErrorOr<StructureField>
  parseTracepointEventFormatLine(const std::string &format_line);

  static StringErrorOr<Structure>
  parseTracepointEventFormat(const std::string &format);

  static std::string normalizeStructureFieldType(const std::string &type);

  friend class ITracepointEvent;
};
} // namespace ebpfpub
