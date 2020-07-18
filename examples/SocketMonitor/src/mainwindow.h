/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>

#include <QCloseEvent>
#include <QMainWindow>

class MainWindow final : public QMainWindow {
  Q_OBJECT

public:
  MainWindow(QWidget *parent = nullptr);
  virtual ~MainWindow() override;

  MainWindow(const MainWindow &) = delete;
  MainWindow &operator=(const MainWindow &) = delete;

protected:
  virtual void closeEvent(QCloseEvent *event) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

private slots:
  void onUpdateModelTimer();
};
