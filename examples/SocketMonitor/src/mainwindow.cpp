/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "mainwindow.h"
#include "model.h"
#include "tracer.h"

#include <QHeaderView>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTimer>

struct MainWindow::PrivateData final {
  std::unique_ptr<Tracer> tracer;

  Model *model{nullptr};
  QTimer model_update_timer;
};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), d(new PrivateData) {

  auto event_table = new QTableView();

  event_table->setAlternatingRowColors(true);

  event_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
  event_table->horizontalHeader()->setStretchLastSection(true);
  event_table->verticalHeader()->hide();

  event_table->setSortingEnabled(true);
  event_table->setSelectionBehavior(QAbstractItemView::SelectRows);

  event_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
  event_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);

  d->model = new Model();

  auto proxy_model = new QSortFilterProxyModel(event_table);
  proxy_model->setSourceModel(d->model);
  event_table->setModel(proxy_model);

  setCentralWidget(event_table);

  d->tracer = std::make_unique<Tracer>();

  connect(&d->model_update_timer, &QTimer::timeout, this,
          &MainWindow::onUpdateModelTimer);

  d->model_update_timer.start(1000);
}

MainWindow::~MainWindow() {
  d->model_update_timer.stop();
  d->tracer.reset();
}

void MainWindow::closeEvent(QCloseEvent *event) {
  auto answer = QMessageBox::question(
      this, tr("Question"),
      tr("Are you sure you want to terminate SocketMonitor?"));

  if (answer != QMessageBox::Yes) {
    event->ignore();
  } else {
    event->accept();
  }
}

void MainWindow::onUpdateModelTimer() {
  auto row_list = d->tracer->getRowList();
  d->model->addRowList(row_list);
}
