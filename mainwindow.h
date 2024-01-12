#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtCore>
#include <QCoreApplication>
#include <QApplication>
#include <QImage>
#include <QMainWindow>
#include <QDebug>
#include <cstdint>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QDataStream>
#include <QByteArray>
#include <QBuffer>
#include <QDataStream>
#include <QImageWriter>
#include <QMessageBox>



#define IDA32_ICON48_SIZE 6021 //48*48
#define IDA32_ICON64_SIZE 9737 //64*64
#define IDA32_ICON96_SIZE 20066 //96*96
#define IDA64_ICON48_SIZE 5862 //48*48
#define IDA64_ICON64_SIZE 9499 //64*64
#define IDA64_ICON96_SIZE 19606 //96*96

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    int idabinFileExists = 1;
    QString idabinFilePath = "";
    QString idabackbinFilePath = "";
    int ida32_png_useful = 1;

    int ida64binFileExists = 1;
    QString ida64binFilePath = "";
    QString ida64backbinFilePath = "";
    int ida64_png_useful = 1;

    QByteArray customIDA32imageData_48;
    QByteArray customIDA32imageData_64;
    QByteArray customIDA32imageData_96;
    QByteArray customIDA64imageData_48;
    QByteArray customIDA64imageData_64;
    QByteArray customIDA64imageData_96;



    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_actionSelectFile_triggered();
    void InsertLog(QString insContent);
    void on_actionChangeIcon_triggered();

    void on_action_IDA32_triggered();

    void on_action_IDA64_triggered();

    void on_actionResetIcon_triggered();

    void on_actionClearLog_triggered();

    void on_actionAbout_triggered();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
