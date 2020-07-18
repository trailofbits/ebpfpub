/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "model.h"

#include <vector>

struct Model::PrivateData final {
  RowList row_list;
};

Model::Model() : d(new PrivateData) {}

Model::~Model() {}

void Model::addRow(Row &row) {
  auto new_row_index = static_cast<int>(d->row_list.size());

  beginInsertRows({}, new_row_index, new_row_index);

  d->row_list.push_back(std::move(row));
  row = {};

  endInsertRows();
}

void Model::addRowList(RowList &row_list) {
  if (row_list.empty()) {
    return;
  }

  auto first_row_index = static_cast<int>(d->row_list.size());
  auto last_row_index = first_row_index + static_cast<int>(row_list.size()) - 1;

  beginInsertRows({}, first_row_index, last_row_index);

  d->row_list.insert(d->row_list.end(),
                     std::make_move_iterator(row_list.begin()),
                     std::make_move_iterator(row_list.end()));

  row_list = {};

  endInsertRows();
}

int Model::rowCount(const QModelIndex &) const {
  return static_cast<int>(d->row_list.size());
}

int Model::columnCount(const QModelIndex &) const { return 10; }

QVariant Model::headerData(int section, Qt::Orientation orientation,
                           int role) const {
  if (orientation != Qt::Horizontal) {
    return {};
  }

  if (role != Qt::DisplayRole) {
    return {};
  }

  switch (section) {
  case 0:
    return tr("Timestamp");

  case 1:
    return tr("Thread ID");

  case 2:
    return tr("Process ID");

  case 3:
    return tr("User ID");

  case 4:
    return tr("Group ID");

  case 5:
    return tr("cgroup ID");

  case 6:
    return tr("Exit code");

  case 7:
    return tr("Executable path");

  case 8:
    return tr("Syscall name");

  case 9:
    return tr("Event data");

  default:
    return {};
  }
}

QVariant Model::data(const QModelIndex &index, int role) const {
  if (role != Qt::DisplayRole) {
    return {};
  }

  if (index.row() < 0 || index.row() > rowCount({})) {
    return {};
  }

  if (index.column() < 0 || index.column() > columnCount({})) {
    return {};
  }

  auto row_number = static_cast<std::size_t>(index.row());
  const auto &row = d->row_list.at(row_number);

  switch (index.column()) {
  case 0:
    return QVariant(static_cast<unsigned long long int>(row.timestamp));

  case 1:
    return QVariant(row.thread_id);

  case 2:
    return QVariant(row.process_id);

  case 3:
    return QVariant(row.user_id);

  case 4:
    return QVariant(row.group_id);

  case 5: {
    auto value = static_cast<unsigned long long int>(row.cgroup_id);
    return QVariant(value);
  }

  case 6: {
    auto value = static_cast<unsigned long long int>(row.exit_code);
    return QVariant(value);
  }

  case 7:
    return QString(row.executable_path.c_str());

  case 8:
    return QString(row.syscall_name.c_str());

  case 9:
    return QString(row.event_data.c_str());

  default:
    return {};
  }
}
