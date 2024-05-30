#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::InsertLog(QString insContent){
    ui->textBrowser->moveCursor(QTextCursor::End);
    ui->textBrowser->insertPlainText(insContent);
    ui->textBrowser->ensureCursorVisible();
}

QStringList runSystemCommand(const QString &program, const QStringList &arguments) {
    QProcess process;
    process.start(program, arguments);
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    QStringList result = QString::fromUtf8(output).split('\n', Qt::SkipEmptyParts);
    return result;
}

QString getIDAVersion(QString filepath){
    QString program = "strings";
    QStringList arguments;
    arguments << filepath;
    QStringList stringsOutput = runSystemCommand(program, arguments);
    QStringList filteredStrings;
    for (int i = 0; i < stringsOutput.size(); ++i) {
        const QString &str = stringsOutput.at(i);
        if (str.contains("<string>") && str.contains("com.hexrays.ida")) {
            filteredStrings.append(str);
            qDebug() << "Next item:" << stringsOutput.at(i + 2);
            int start = stringsOutput.at(i + 2).indexOf("<string>") + QString("<string>").length();
            int end = stringsOutput.at(i + 2).indexOf("</string>");
            QString extractedContent = stringsOutput.at(i + 2).mid(start, end - start);
            return extractedContent;
        }
    }
    return "";
}


void MainWindow::setIDA_ICON_SIZE(){
    if(IDAVersion == "7.5.200519"){
        IDA32_ICON48_SIZE = 5901;
        IDA32_ICON64_SIZE = 18062;
        IDA32_ICON96_SIZE = 113505;
        IDA64_ICON48_SIZE = 5901;
        IDA64_ICON64_SIZE = 18062;
        IDA64_ICON96_SIZE = 129065;
    }
    if(IDAVersion == "8.3.230608"){
        IDA32_ICON48_SIZE = 6021;
        IDA32_ICON64_SIZE = 9737;
        IDA32_ICON96_SIZE = 20066;
        IDA64_ICON48_SIZE = 5862;
        IDA64_ICON64_SIZE = 9499;
        IDA64_ICON96_SIZE = 19606;
    }

    if(IDAVersion == "8.4.240527"){ //8.4SP2
        IDA32_ICON48_SIZE = 6021;
        IDA32_ICON64_SIZE = 9737;
        IDA32_ICON96_SIZE = 20066;
        IDA64_ICON48_SIZE = 5862;
        IDA64_ICON64_SIZE = 9499;
        IDA64_ICON96_SIZE = 19606;
    }

}



void MainWindow::on_actionSelectFile_triggered()
{
    QString dlgTitle="选择一个文件";
    QString filter="程序文件(*.app);;所有文件(*.*)";
    QString idaappFilePath=QFileDialog::getOpenFileName(this,dlgTitle,"/Applications",filter);
    InsertLog("[*]选择IDA.app文件: "+idaappFilePath+"\n");
    InsertLog("[*]正在选择ida文件...\n");
    idabinFilePath=idaappFilePath+"/Contents/MacOS/ida";
    ida64binFilePath=idaappFilePath+"/../ida64.app/Contents/MacOS/ida64";
    QFile idabinFile(idabinFilePath);
    QFile ida64binFile(idabinFilePath);

    if(idabinFile.exists() != 0 && ida64binFile.exists() != 0){
        InsertLog("[+]选择ida文件成功: "+idabinFilePath+"\n");
        InsertLog("[+]选择ida64文件成功: "+ida64binFilePath+"\n");
        idabinFileExists = 0;
    }else{
        InsertLog("[-]选择ida文件失败!\n");
    }
    IDAVersion = getIDAVersion(idabinFilePath);
    qDebug() << IDAVersion;
    if(IDAVersion == ""){
        InsertLog("[-]未检测到IDA版本!\n");
        return;
    }
    InsertLog("[+]检测到IDA版本为"+IDAVersion+"\n");

}


void MainWindow::on_actionChangeIcon_triggered()
{
    if(IDAVersion == ""){
        InsertLog("[-]未检测到IDA版本!\n");
        return;
    }
    if(idabinFileExists == 0){
        idabackbinFilePath = idabinFilePath.chopped(3) + "CustomIDA_ida_bak";
        ida64backbinFilePath = ida64binFilePath.chopped(5) + "CustomIDA_ida64_bak";
//        InsertLog("debug->"+ida64backbinFilePath+"\n");
        QFile idabackbinFile(idabackbinFilePath);
        QFile ida64backbinFile(ida64backbinFilePath);
        if(idabackbinFile.exists() != 0 && ida64backbinFile.exists() != 0){
            InsertLog("[*]存在备份文件: "+idabackbinFilePath+"\n");
            InsertLog("[*]存在备份文件: "+ida64backbinFilePath+"\n");
        }else{
            InsertLog("[*]不存在备份文件, 正在创建...\n");
            if(QFile::copy(idabinFilePath, idabackbinFilePath)){
                InsertLog("[*]创建备份文件成功: "+idabackbinFilePath+"\n");
            }else{
                InsertLog("[-]创建备份文件失败\n");
            }
            if(QFile::copy(ida64binFilePath, ida64backbinFilePath)){
                InsertLog("[*]创建备份文件成功: "+ida64backbinFilePath+"\n");
            }else{
                InsertLog("[-]创建备份文件失败\n");
            }
        }
        if(ida32_png_useful == 0){
            InsertLog("[+]检测到IDA32资源文件\n");
        }
        if(ida64_png_useful == 0){
            InsertLog("[+]检测到IDA64资源文件\n");
        }
        if(ida32_png_useful == 1 && ida64_png_useful == 1){
            InsertLog("[-]未检测到IDA图标资源文件\n");
            return;
        }

        //####匹配
        if(ida32_png_useful == 0){
            QFile idabinFile(idabinFilePath);
            if(idabinFile.open(QIODevice::ReadWrite)){
                QByteArray data = idabinFile.readAll();  // 读取整个文件内容
                QByteArray startPattern("\x89\x50\x4E\x47");  // 要搜索的起始字节序列
                QByteArray endPattern("\xAE\x42\x60\x82");    // 要搜索的结束字节序列

                int startIdx = 0;
                int endIdx = 0;

                while (startIdx != -1 && endIdx != -1 && startIdx <= endIdx) {
                    startIdx = data.indexOf(startPattern, endIdx);
                    endIdx = data.indexOf(endPattern, startIdx);

                    if (startIdx != -1 && endIdx != -1 && startIdx <= endIdx) {
                        int matchSize = endIdx - startIdx + endPattern.size();
                            if (matchSize == IDA32_ICON48_SIZE) {
                                qDebug() << "ida32_icon48 " << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                                customIDA32imageData_48.resize(IDA32_ICON48_SIZE);
                                data.replace(startIdx, IDA32_ICON48_SIZE, customIDA32imageData_48);
                                idabinFile.seek(0);
                                idabinFile.write(data);
                                idabinFile.resize(data.size());
                                InsertLog("[+]IDA 48*48 png资源替换成功!(ida32_icon48->Offset:" + QString("0x%1").arg(startIdx, 0, 16) +")\n");
                            }else if(matchSize == IDA32_ICON64_SIZE){
                                qDebug() << "ida32_icon64 " << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                                customIDA32imageData_64.resize(IDA32_ICON64_SIZE);
                                data.replace(startIdx, IDA32_ICON64_SIZE, customIDA32imageData_64);
                                idabinFile.seek(0);
                                idabinFile.write(data);
                                idabinFile.resize(data.size());
                                InsertLog("[+]IDA 64*64 png资源替换成功!(ida32_icon64->Offset:" + QString("0x%1").arg(startIdx, 0, 16) +")\n");
                            }else if(matchSize == IDA32_ICON96_SIZE){
                                qDebug() << "ida32_icon96 " << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                                customIDA32imageData_96.resize(IDA32_ICON96_SIZE);
                                data.replace(startIdx, IDA32_ICON96_SIZE, customIDA32imageData_96);
                                idabinFile.seek(0);
                                idabinFile.write(data);
                                idabinFile.resize(data.size());
                                InsertLog("[+]IDA 96*96 png资源替换成功!(ida32_icon96->Offset:" + QString("0x%1").arg(startIdx, 0, 16) +")\n");
                            }
                        qDebug() << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                    }
                }
                idabinFile.close();
            }else{
                InsertLog("[-]打开文件失败: "+idabinFilePath+"\n");
            }
            ida32_png_useful = 1;
        }
        if(ida64_png_useful == 0){
            QFile ida64binFile(ida64binFilePath);
            if(ida64binFile.open(QIODevice::ReadWrite)){
                QByteArray data = ida64binFile.readAll();  // 读取整个文件内容
                QByteArray startPattern("\x89\x50\x4E\x47");  // 要搜索的起始字节序列
                QByteArray endPattern("\xAE\x42\x60\x82");    // 要搜索的结束字节序列

                int startIdx = 0;
                int endIdx = 0;

                while (startIdx != -1 && endIdx != -1 && startIdx <= endIdx) {
                    startIdx = data.indexOf(startPattern, endIdx);
                    endIdx = data.indexOf(endPattern, startIdx);

                    if (startIdx != -1 && endIdx != -1 && startIdx <= endIdx) {
                        int matchSize = endIdx - startIdx + endPattern.size();
                            if (matchSize == IDA64_ICON48_SIZE) {
                                qDebug() << "ida64_icon48 " << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                                customIDA64imageData_48.resize(IDA64_ICON48_SIZE);
                                data.replace(startIdx, IDA64_ICON48_SIZE, customIDA64imageData_48);
                                ida64binFile.seek(0);
                                ida64binFile.write(data);
                                ida64binFile.resize(data.size());
                                InsertLog("[+]IDA64 48*48 png资源替换成功! (ida64_icon48->Offset:" + QString("0x%1").arg(startIdx, 0, 16) +")\n");
                            }else if(matchSize == IDA64_ICON64_SIZE){
                                qDebug() << "ida64_icon64 " << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                                customIDA64imageData_64.resize(IDA64_ICON64_SIZE);
                                data.replace(startIdx, IDA64_ICON64_SIZE, customIDA64imageData_64);
                                ida64binFile.seek(0);
                                ida64binFile.write(data);
                                ida64binFile.resize(data.size());
                                InsertLog("[+]IDA64 64*64 png资源替换成功!(ida64_icon64->Offset:" + QString("0x%1").arg(startIdx, 0, 16) +")\n");
                            }else if(matchSize == IDA64_ICON96_SIZE){
                                qDebug() << "ida64_icon96 " << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                                customIDA64imageData_96.resize(IDA64_ICON96_SIZE);
                                data.replace(startIdx, IDA64_ICON96_SIZE, customIDA64imageData_96);
                                ida64binFile.seek(0);
                                ida64binFile.write(data);
                                ida64binFile.resize(data.size());
                                InsertLog("[+]IDA64 96*96 png资源替换成功!(ida64_icon96->Offset:" + QString("0x%1").arg(startIdx, 0, 16) +")\n");
                            }
    //                    qDebug() << "Offset:" << QString("0x%1").arg(startIdx, 0, 16) << "Size:" << matchSize;
                    }
                }
                ida64binFile.close();
            }else{
                InsertLog("[-]打开文件失败: "+ida64binFilePath+"\n");
            }
            ida64_png_useful = 1;
        }

    }else{
        InsertLog("[-]选择文件失败, 请检查IDA.app是否加载或路径是否正确.\n");
    }
}


void MainWindow::on_action_IDA32_triggered()
{
    if(IDAVersion == ""){
        InsertLog("[-]请指定IDA.app文件!\n");
        return;
    }
    setIDA_ICON_SIZE();
    QString customIDA32_png_path = QFileDialog::getOpenFileName(nullptr, "", "", "PNG 图片 (*.png)");
    if (!customIDA32_png_path.isEmpty()) {
        QImage customIDA32image(customIDA32_png_path);
        if (!customIDA32image.isNull()) {

            QByteArray customIDA32imageData;
            QBuffer customIDA32imageBuffer(&customIDA32imageData);
            customIDA32image.save(&customIDA32imageBuffer, "PNG");

            QImage customIDA32image_48 = customIDA32image.scaled(48, 48, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QBuffer customIDA32imageBuffer_48(&customIDA32imageData_48);
            customIDA32image_48.save(&customIDA32imageBuffer_48, "PNG");

            QImage customIDA32image_64 = customIDA32image.scaled(64, 64, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QBuffer customIDA32imageBuffer_64(&customIDA32imageData_64);
            customIDA32image_64.save(&customIDA32imageBuffer_64, "PNG");

            QImage customIDA32image_96 = customIDA32image.scaled(96, 96, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QBuffer customIDA32imageBuffer_96(&customIDA32imageData_96);
            customIDA32image_96.save(&customIDA32imageBuffer_96, "PNG");

            qDebug() << "customIDA32imageData.size() ->" << customIDA32imageData.size();
            qDebug() << "customIDA32imageData_48.size() ->" << customIDA32imageData_48.size();
            qDebug() << "customIDA32imageData_64.size() ->" << customIDA32imageData_64.size();
            qDebug() << "customIDA32imageData_96.size() ->" << customIDA32imageData_96.size();
            qDebug() << "IDA32_ICON96_SIZE ->" << IDA32_ICON96_SIZE;

            if (customIDA32imageData_96.size() < IDA32_ICON96_SIZE-1) {
                InsertLog("[+]文件符合要求, 点击“变更图标”进行替换.\n");
                ida32_png_useful = 0;
//                QString customIDA32image_48_path = QDir::currentPath() + "/customIDA32image_48.png";
//                customIDA32image_48.save(customIDA32image_48_path, "PNG");
//                QString customIDA32image_64_path = QDir::currentPath() + "/customIDA32image_64.png";
//                customIDA32image_64.save(customIDA32image_64_path, "PNG");
//                QString customIDA32image_96_path = QDir::currentPath() + "/customIDA32image_96.png";
//                customIDA32image_96.save(customIDA32image_96_path, "PNG");
            }else{
                InsertLog("[-]图片太大啦!\n");
            }
        }else{
            InsertLog("[-]打开文件失败\n");
        }
    }else{
        InsertLog("[-]没有选择文件\n");
    }

}


void MainWindow::on_action_IDA64_triggered()
{
    if(IDAVersion == ""){
        InsertLog("[-]请指定IDA.app文件!\n");
        return;
    }
    setIDA_ICON_SIZE();
    QString customIDA64_png_path = QFileDialog::getOpenFileName(nullptr, "", "", "PNG 图片 (*.png)");
    if (!customIDA64_png_path.isEmpty()) {
        QImage customIDA64image(customIDA64_png_path);
        if (!customIDA64image.isNull()) {

            QByteArray customIDA64imageData;
            QBuffer customIDA64imageBuffer(&customIDA64imageData);
            customIDA64image.save(&customIDA64imageBuffer, "PNG");

            QImage customIDA64image_48 = customIDA64image.scaled(48, 48, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QBuffer customIDA64imageBuffer_48(&customIDA64imageData_48);
            customIDA64image_48.save(&customIDA64imageBuffer_48, "PNG");

            QImage customIDA64image_64 = customIDA64image.scaled(64, 64, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QBuffer customIDA64imageBuffer_64(&customIDA64imageData_64);
            customIDA64image_64.save(&customIDA64imageBuffer_64, "PNG");

            QImage customIDA64image_96 = customIDA64image.scaled(96, 96, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QBuffer customIDA64imageBuffer_96(&customIDA64imageData_96);
            customIDA64image_96.save(&customIDA64imageBuffer_96, "PNG");

            qDebug() << "customIDA64imageData.size() ->" << customIDA64imageData.size();
            qDebug() << "customIDA64imageData_48.size() ->" << customIDA64imageData_48.size();
            qDebug() << "customIDA64imageData_64.size() ->" << customIDA64imageData_64.size();
            qDebug() << "customIDA64imageData_96.size() ->" << customIDA64imageData_96.size();

            if (customIDA64imageData_96.size() < IDA64_ICON96_SIZE-1) {
                InsertLog("[+]文件符合要求, 点击“变更图标”进行替换.\n");
                ida64_png_useful = 0;
                                QString customIDA64image_48_path = QDir::currentPath() + "/customIDA64image_48.png";
                                customIDA64image_48.save(customIDA64image_48_path, "PNG");
                                QString customIDA64image_64_path = QDir::currentPath() + "/customIDA64image_64.png";
                                customIDA64image_64.save(customIDA64image_64_path, "PNG");
                                QString customIDA64image_96_path = QDir::currentPath() + "/customIDA64image_96.png";
                                customIDA64image_96.save(customIDA64image_96_path, "PNG");
            }else{
                InsertLog("[-]图片太大啦!\n");
            }
        }else{
            InsertLog("[-]打开文件失败\n");
        }
    }else{
        InsertLog("[-]没有选择文件\n");
    }

}


void MainWindow::on_actionResetIcon_triggered()
{
    if(idabinFileExists == 0){
        idabackbinFilePath = idabinFilePath.chopped(3) + "CustomIDA_ida_bak";
        ida64backbinFilePath = ida64binFilePath.chopped(5) + "CustomIDA_ida64_bak";
        QFile::remove(idabinFilePath);
        if (QFile::copy(idabackbinFilePath, idabinFilePath)) {
            InsertLog("[+]文件还原成功: " + idabinFilePath+"\n");
        } else {
            InsertLog("[+]文件还原失败!\n");
        }
        QFile::remove(ida64binFilePath);
        if (QFile::copy(ida64backbinFilePath, ida64binFilePath)) {
            InsertLog("[+]文件还原成功: " + ida64binFilePath+"\n");
        } else {
            InsertLog("[+]文件还原失败!\n");
        }
    }else{
        InsertLog("[-] 检查是否选择IDA.app\n");
    }

}


void MainWindow::on_actionClearLog_triggered()
{
    ui->textBrowser->clear();
}


void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::information(nullptr, "帮助", "目前支持列表: \n"
                            "IDA pro 7.5.200519 for MacOS\n"
                            "IDA pro 8.3.230608 for MacOS\n"
                            "IDA pro 8.4.240527 for MacOS\n"
                            "\n"
                            "项目地址: https://github.com/yywz1999/CustomIDA"
    );
}

