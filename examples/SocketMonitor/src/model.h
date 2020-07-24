/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <QAbstractTableModel>

#include <ebpfpub/ifunctiontracer.h>

class Model final : public QAbstractTableModel {
  Q_OBJECT

public:
  struct Row final {
    std::uint64_t timestamp{0U};
    pid_t thread_id{0};
    pid_t process_id{0};
    uid_t user_id{0};
    gid_t group_id{0};
    std::uint64_t cgroup_id{0U};
    std::uint64_t exit_code{0U};

    std::string executable_path;
    std::string syscall_name;
    std::string event_data;
  };

  using RowList = std::vector<Row>;

  Model();
  virtual ~Model() override;

  void addRow(Row &row);
  void addRowList(RowList &row_list);

  virtual int rowCount(const QModelIndex &) const override;
  virtual int columnCount(const QModelIndex &) const override;

  virtual QVariant headerData(int section, Qt::Orientation orientation,
                              int role) const override;

  virtual QVariant data(const QModelIndex &index, int role) const override;

  Model(const Model &) = delete;
  Model &operator=(const Model &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
