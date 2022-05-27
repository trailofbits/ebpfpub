/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>
#include <sstream>
#include <unordered_set>

#include <tob/error/stringerror.h>

namespace tob::ebpfpub {

class KallsymsParser final {
public:
  using Ptr = std::unique_ptr<KallsymsParser>;

  static StringErrorOr<Ptr> create(const std::string &path);
  ~KallsymsParser();

  bool contains(const std::string &symbol_name);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  KallsymsParser(const std::string &path);

public:
  using SymbolList = std::unordered_set<std::string>;

  static StringErrorOr<SymbolList> parseBuffer(std::stringstream read_buffer);

  static bool containsSymbol(const SymbolList &symbol_list,
                             const std::string &symbol_name);
};

} // namespace tob::ebpfpub
