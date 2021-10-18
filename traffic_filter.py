from netrc import netrc

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt4agg import FigureCanvas
import socket
import netifaces as ni
import subprocess
import pyshark
from scapy.all import *
from threading import Thread
import pandas
import time
import os
# from mac_vendor_lookup import MacLookup

from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2

        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        if ssid != '':
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
            #freq
            freq = packet[RadioTap].Channel
            # print(bssid)
            # vendor = MacLookup().lookup(bssid.upper())
            tuple = (bssid, dbm_signal, channel, crypto, freq)

            networkMap[ssid] = tuple
            # networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, freq)


ip_frequencies_departing = {}
ip_frequencies_incoming = {}
local_ip = ""
address_to_block = ""
open_ports = []
time_to_capture = 0

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Freq"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

networkMap = {}

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _from_utf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8


    def _translate(context, text, disambiguation):
        return QtGui.QApplication.translate(context, text, disambiguation, _encoding)
except AttributeError:
    def _translate(context, text, disambiguation):
        return QtGui.QApplication.translate(context, text, disambiguation)


class MplWidget(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        figure = plt.figure(figsize=(20, 10))
        plt.subplots_adjust(bottom=0.35)
        self.canvas = FigureCanvas(figure)

        self.vertical_layout = QVBoxLayout()
        self.vertical_layout.addWidget(self.canvas)

        self.setLayout(self.vertical_layout)

    def update(self, ip_frequencies):
        print('Updating graph with values:')
        for key in ip_frequencies.keys():
            print(key + ' ' + str(ip_frequencies[key]))
        print()

        self.vertical_layout.removeWidget(self.canvas)
        figure = plt.figure(figsize=(20, 10))
        plt.subplots_adjust(bottom=0.35)
        plt.xticks(rotation='vertical')
        plt.bar(ip_frequencies.keys(), ip_frequencies.values(), align='edge', width=0.2)
        for a, b in zip(ip_frequencies.keys(), ip_frequencies.values()):
            plt.text(a, b, str(b))

        self.canvas = FigureCanvas(figure)
        self.vertical_layout.addWidget(self.canvas)


def show_dialog(dialog_type, title, text):
    msg = QMessageBox()
    msg.setIcon(dialog_type)

    msg.setText(text)
    msg.setWindowTitle(title)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()


def update_time_to_capture(new_time_to_capture):
    global time_to_capture
    try:
        time_to_capture = int(new_time_to_capture)
    except ValueError:
        time_to_capture = 0


def update_address_to_block(new_address_to_block):
    global address_to_block
    address_to_block = new_address_to_block


class UiMainWindow(object):
    def __init__(self, main_window):
        main_window.setObjectName(_from_utf8("main_window"))
        main_window.resize(710, 600)
        self.central_widget = QtGui.QWidget(main_window)
        self.central_widget.setObjectName(_from_utf8("central_widget"))

        self.horizontal_layout_2 = QtGui.QHBoxLayout(self.central_widget)
        self.horizontal_layout_2.setObjectName(_from_utf8("horizontal_layout_2"))

        self.vertical_layout = QtGui.QVBoxLayout()
        self.vertical_layout.setObjectName(_from_utf8("vertical_layout"))

        self.label_ip = QtGui.QLabel(self.central_widget)
        self.label_ip.setObjectName(_from_utf8("label_ip"))
        self.vertical_layout.addWidget(self.label_ip)

        spacer_item = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Maximum)
        self.vertical_layout.addItem(spacer_item)

        self.label_time_to_capture = QtGui.QLabel(self.central_widget)
        self.label_time_to_capture.setObjectName(_from_utf8("label_time_to_capture"))
        self.vertical_layout.addWidget(self.label_time_to_capture)

        self.line_edit_time_to_capture = QtGui.QLineEdit(self.central_widget)
        self.line_edit_time_to_capture.setObjectName(_from_utf8("line_edit_time_to_capture"))
        self.vertical_layout.addWidget(self.line_edit_time_to_capture)
        self.line_edit_time_to_capture.setValidator(QIntValidator())
        self.line_edit_time_to_capture.textChanged.connect(update_time_to_capture)

        self.button_capture = QtGui.QPushButton(self.central_widget)
        self.button_capture.setEnabled(True)
        self.button_capture.setMinimumSize(QtCore.QSize(0, 75))
        self.button_capture.setObjectName(_from_utf8("button_capture"))
        self.vertical_layout.addWidget(self.button_capture)
        self.button_capture.clicked.connect(self.handle_capture)

        spacer_item = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.vertical_layout.addItem(spacer_item)

        self.label_block = QtGui.QLabel(self.central_widget)
        self.label_block.setObjectName(_from_utf8("label_block"))
        self.vertical_layout.addWidget(self.label_block)

        self.line_edit_block = QtGui.QLineEdit(self.central_widget)
        self.line_edit_block.setObjectName(_from_utf8("line_edit_block"))
        self.vertical_layout.addWidget(self.line_edit_block)
        self.line_edit_block.textChanged.connect(update_address_to_block)

        self.button_block = QtGui.QPushButton(self.central_widget)
        self.button_block.setMinimumSize(QtCore.QSize(0, 75))
        self.button_block.setObjectName(_from_utf8("button_block"))
        self.vertical_layout.addWidget(self.button_block)
        self.button_block.clicked.connect(self.handle_block)

        self.horizontal_layout_2.addLayout(self.vertical_layout)

        spacer_item1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontal_layout_2.addItem(spacer_item1)

        self.vertical_layout_2 = QtGui.QVBoxLayout()
        self.vertical_layout_2.setObjectName(_from_utf8("vertical_layout_2"))

        self.label_incoming = QtGui.QLabel(self.central_widget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_incoming.setIndent(30)
        self.label_incoming.setFont(font)
        self.label_incoming.setObjectName(_from_utf8("label_incoming"))
        self.vertical_layout_2.addWidget(self.label_incoming)

        self.widget_plot_incoming = MplWidget(self.central_widget)
        self.widget_plot_incoming.setObjectName(_from_utf8("widget_plot_incoming"))
        self.vertical_layout_2.addWidget(self.widget_plot_incoming)

        spacer_item2 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.vertical_layout_2.addItem(spacer_item2)

        self.label_departing = QtGui.QLabel(self.central_widget)
        self.label_departing.setFont(font)
        self.label_departing.setIndent(30)
        self.label_departing.setObjectName(_from_utf8("label_departing"))
        self.vertical_layout_2.addWidget(self.label_departing)

        self.widget_plot_departing = MplWidget(self.central_widget)
        self.widget_plot_departing.setObjectName(_from_utf8("widget_plot_departing"))
        self.vertical_layout_2.addWidget(self.widget_plot_departing)

        self.horizontal_layout_2.addLayout(self.vertical_layout_2)

        main_window.setCentralWidget(self.central_widget)

        self.re_translate_ui(main_window)
        QtCore.QMetaObject.connectSlotsByName(main_window)

    def handle_capture(self):
        if time_to_capture <= 0:
            show_dialog(QMessageBox.Critical, 'Error', 'The time to capture must be a positive value!')
        else:
            self.button_capture.setText('Now capturing, please wait...')
            self.button_capture.setEnabled(False)
            start_capture(time_to_capture)
            show_dialog(QMessageBox.Information, 'Info', 'Capturing finished!')
            self.button_capture.setEnabled(True)
            self.button_capture.setText('Start Capturing')
            self.update_graphs()

    def handle_block(self):
        if len(address_to_block) <= 0:
            show_dialog(QMessageBox.Critical, 'Error', 'The address to block must not be empty')
        else:
            block_address(address_to_block)
            show_dialog(QMessageBox.Information, 'Info',
                        'Successfully added DROP rules for the address ' + address_to_block + ' in the INPUT and' +
                        ' OUTPUT chains!')
            self.line_edit_block.setText("")

    def update_graphs(self):
        self.widget_plot_incoming.update(ip_frequencies_incoming)
        self.widget_plot_departing.update(ip_frequencies_departing)

    def re_translate_ui(self, main_window):
        main_window.setWindowTitle(_translate("main_window", "Traffic Filter", None))
        self.label_time_to_capture.setText(_translate("main_window", "Enter the capture time in seconds:", None))
        self.button_capture.setText(_translate("main_window", "Start Capturing", None))
        self.label_block.setText(_translate("main_window", "Enter the address/IP you want to block:", None))
        self.button_block.setText(_translate("main_window", "Block address", None))
        self.label_incoming.setText(_translate("main_window", "Incoming traffic", None))
        self.label_departing.setText(_translate("main_window", "Departing Traffic", None))
        self.label_ip.setText(_translate("main_window", "IP address of current machine: " + local_ip, None))


def get_local_ip():
    global local_ip
    local_ip = ni.ifaddresses('wlan0')[ni.AF_INET][0]['addr']


def get_open_ports():
    global open_ports
    for port in range(65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex(('127.0.0.1', port))

        if result == 0:
            print('socket is open: ', port, ' is listening')
            open_ports.append(port)
        s.close()


def start_capture(capture_time):
    global ip_frequencies_incoming
    global ip_frequencies_departing
    ip_frequencies_departing = {}
    ip_frequencies_incoming = {}
    capture = pyshark.LiveCapture(interface='wlan0')
    try:
        capture.apply_on_packets(pkt_callback, timeout=capture_time)
    except:
        pass


def count_frequencies(pkt):
    try:
        if pkt.ip.src == local_ip:
            if pkt.ip.dst in ip_frequencies_departing.keys():
                ip_frequencies_departing[pkt.ip.dst] += 1
            else:
                ip_frequencies_departing[pkt.ip.dst] = 1

        if pkt.ip.dst == local_ip:
            if pkt.ip.src in ip_frequencies_incoming.keys():
                ip_frequencies_incoming[pkt.ip.src] += 1
            else:
                ip_frequencies_incoming[pkt.ip.src] = 1
    except:
        print('Exception in counting frequencies')


def port_check(pkt):
    try:
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        print('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))

        if str(src_addr) == local_ip:
            if int(src_port) in open_ports:
                print('Port is open', src_port)
            elif int(src_port) not in open_ports:
                print('Port INVALID', src_port)

        elif str(dst_addr) == local_ip:
            if int(dst_port) in open_ports:
                print('Port is open', dst_port)
            elif int(dst_port) not in open_ports:
                print('Port INVALID', dst_port)
    except:
        print('Exception while checking ports')


def dns_query(pkt):
    try:
        if pkt.dns.qry_name:
            print('DNS Request from %s -> %s: %s' % (pkt.ip.src, pkt.ip.dst, pkt.dns.qry_name))
        elif pkt.dns.resp_name:
            print('DNS Response from %s -> %s: %s' % (pkt.ip.src, pkt.ip.dst, pkt.dns.qry_name))
    except:
        print('Not a DNS query')


def pkt_callback(pkt):
    try:
        count_frequencies(pkt)
        port_check(pkt)
        dns_query(pkt)
        # print(pkt.eth.field_names)
        # parsing the packet
        # print("IP Layer:")
        # protocol = pkt.transport_layer
        # src_addr = pkt.ip.src
        # src_port = pkt[pkt.transport_layer].srcport
        # dst_addr = pkt.ip.dst
        # st_port = pkt[pkt.transport_layer].dstport
        # print('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))
        # print("payload: ", pkt.tcp.payload)
        # print('ETH layer')
        # print('MAC sursa: ', pkt.eth.scr, 'MAC destinatie: ', pkt.eth.dst)
    except:
        print('Just arrived and threw exception: ')
    
    print(pkt)



def block_address(address):
    cmd = "/sbin/iptables -A INPUT -s " + address + " -j DROP"
    print(cmd)
    subprocess.call(cmd, shell=True)

    cmd = "/sbin/iptables -A OUTPUT -s " + address + " -j DROP"
    print(cmd)
    subprocess.call(cmd, shell=True)



def print_all():
    while True:
        os.system("clear")
        for ssid in networkMap.keys():
            bssid, dbm_signal, channel, crypto, freq = networkMap[ssid]
            print(ssid, ": MAC: ", bssid, " Signal: ", dbm_signal, " Channel: ", channel, " Crypto: ", crypto, " Freq: ", freq)

        time.sleep(1)

# def change_channel():
#     ch = 1
#     while True:
#         os.system(f"iwconfig {interface} channel {ch}")
#         # switch channel from 1 to 14 each 0.5s
#         ch = ch % 14 + 1
#         time.sleep(0.5)

if __name__ == "__main__":
    import sys

    get_local_ip()
    print("Local IP from wlan0: ", local_ip)
    get_open_ports()
    print("Open ports on the machine: ", open_ports)

    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = UiMainWindow(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

    # # interface name, check using iwconfig
    # interface = "wlan0"
    # # start the thread that prints all the networks
    # printer = Thread(target=print_all)
    # printer.daemon = True
    # printer.start()
    # # start the channel changer
    # channel_changer = Thread(target=change_channel)
    # channel_changer.daemon = True
    # channel_changer.start()
    # # start sniffing
    # sniff(prn=callback, iface=interface)