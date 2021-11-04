/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "kallsymsparser.h"

#include <fstream>

namespace tob::ebpfpub {

struct KallsymsParser::PrivateData final {
  SymbolList symbol_list;
};

StringErrorOr<KallsymsParser::Ptr>
KallsymsParser::create(const std::string &path) {
  try {
    return Ptr(new KallsymsParser(path));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

KallsymsParser::~KallsymsParser() {}

bool KallsymsParser::contains(const std::string &symbol_name) {
  return containsSymbol(d->symbol_list, symbol_name);
}

KallsymsParser::KallsymsParser(const std::string &path) : d(new PrivateData) {
  std::stringstream read_buffer;

  {
    std::fstream input_file(path, std::ios::in);
    if (!input_file) {
      throw StringError::create("Failed to open the following path: " + path);
    }

    read_buffer << input_file.rdbuf();
  }

  auto symbol_list_exp = parseBuffer(std::move(read_buffer));
  if (!symbol_list_exp.succeeded()) {
    throw symbol_list_exp.error();
  }

  d->symbol_list = symbol_list_exp.takeValue();
}

StringErrorOr<KallsymsParser::SymbolList>
KallsymsParser::parseBuffer(std::stringstream read_buffer) {
  KallsymsParser::SymbolList symbol_list;

  std::string current_line;
  while (std::getline(read_buffer, current_line)) {
    auto symbol_name_start = current_line.find_last_of(" ");
    if (symbol_name_start == std::string::npos) {
      return StringError::create("Invalid line format: " + current_line);
    }

    ++symbol_name_start;
    if (symbol_name_start >= current_line.size()) {
      return StringError::create("Invalid line format: " + current_line);
    }

    auto symbol_name_end = current_line.find_last_of("\t");
    if (symbol_name_end == std::string::npos) {
      symbol_name_end = current_line.size();
    }

    auto symbol_name = current_line.substr(symbol_name_start,
                                           symbol_name_end - symbol_name_start);

    symbol_list.insert(std::move(symbol_name));
  }

  return symbol_list;
}

bool KallsymsParser::containsSymbol(
    const KallsymsParser::SymbolList &symbol_list,
    const std::string &symbol_name) {
  return symbol_list.count(symbol_name) > 0;
}

} // namespace tob::ebpfpub
