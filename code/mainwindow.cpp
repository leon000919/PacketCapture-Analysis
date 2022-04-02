#include "mainwindow.h"
#include "ui_mainwindow.h"
#include<pcap.h>
#include "func_pcap.h"
#include<string.h>
#include<dialog.h>
#include <QFile>
#include<time.h>
#include<sstream>
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];                          //错误信息
char *dev;                                              //网络设备接口
struct bpf_program filter;                              //BPF过滤规则
char filter_string[10]={};
int num;
bpf_u_int32 net_mask;                                   //网络掩码
bpf_u_int32 net_ip;                                     //网络地址
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    dev = pcap_lookupdev(errbuf);
    pcap_lookupnet(dev, &net_ip, &net_mask, errbuf);
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    connect(this,SIGNAL(sendData(QString)),Dlg,SLOT(getData(QString)));
}

MainWindow::~MainWindow()
{
    delete ui;
    pcap_close(handle);
}

void MainWindow::on_radioButton_clicked()
{
    memset(filter_string,0,10);
    strcpy(filter_string,"tcp");
}

void MainWindow::on_radioButton_2_clicked()
{
    memset(filter_string,0,10);
    strcpy(filter_string,"udp");
}

void MainWindow::on_radioButton_3_clicked()
{
    memset(filter_string,0,10);
    strcpy(filter_string,"icmp");
}

void MainWindow::on_radioButton_4_clicked()
{
    memset(filter_string,0,10);
    strcpy(filter_string,"arp");
}

void MainWindow::on_spinBox_editingFinished()
{
    num=ui->spinBox->value();
}

void MainWindow::on_pushButton_clicked()
{
    str="";
    packet_number=1;
    pcap_compile(handle, &filter, filter_string, 0, net_ip);
    pcap_setfilter(handle, &filter);
    string tmp;
    tmp=dev;
    str+="网络接口："+tmp+"\n";
    if(num == 0)
    {
        num = 10;
    }
    pcap_loop(handle, num, ethernet_protocol_packet_callback, NULL);
    QString qstr=QString::fromStdString(str);
    QString filename;
    filename ="./data.txt";
    QFile f(filename);
    if(f.open(QIODevice::ReadWrite | QIODevice::Append | QIODevice::Text))
        {
        time_t now = time(NULL);
        tm* tm_t = localtime(&now);
        stringstream ss;
        ss << "捕获时间:" << tm_t->tm_year + 1900 << "/" << tm_t->tm_mon + 1 << "/" << tm_t->tm_mday << "       "
           << tm_t->tm_hour << ":" << tm_t->tm_min << ":" << tm_t->tm_sec << "\n";
        str += "\n\n";
        const std::string& tmp = ss.str();
        const char* temp1 = tmp.c_str();
        const char* temp2 = str.c_str();
        f.write(temp1);
        f.write(temp2);
        f.close();
        }
    emit sendData(qstr);
    Dlg->show();

}
