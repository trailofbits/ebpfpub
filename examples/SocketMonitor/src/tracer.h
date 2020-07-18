/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include "model.h"

#include <memory>

class Tracer final {
public:
  Tracer();
  ~Tracer();

  Model::RowList getRowList() const;

  Tracer(const Tracer &) = delete;
  Tracer &operator=(const Tracer &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  void eventThread();
};
