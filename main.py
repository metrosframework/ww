 
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, hexdump
from scapy.arch import get_windows_if_list  # For Windows
from scapy.arch import get_if_list          # For Linux/Unix
from datetime import datetime
import sys, time
import threading
import queue, pywinstyles
import psutil
import socket
from darktheme.widget_template import DarkApplication, DarkPalette

class PacketSniffer(QMainWindow):
    PROTOCOL_COLORS = {
        # Web протоколы
        'HTTP': {
            'normal': QColor(231, 230, 255),    # Светло-фиолетовый
            'alternate': QColor(241, 240, 255),
            'text': QColor(0, 0, 0)  # Черный текст
        },
        'HTTPS': {
            'normal': QColor(231, 230, 255),
            'alternate': QColor(241, 240, 255),
            'text': QColor(0, 0, 0)
        },
        
        # Почтовые протоколы
        'SMTP': {
            'normal': QColor(238, 236, 225),    # Бежевый
            'alternate': QColor(248, 246, 235),
            'text': QColor(0, 0, 0)
        },
        'POP': {
            'normal': QColor(238, 236, 225),
            'alternate': QColor(248, 246, 235),
            'text': QColor(0, 0, 0)
        },
        
        # Базовые протоколы
        'TCP': {
            'normal': QColor(231, 230, 255),    # Светло-фиолетовый
            'alternate': QColor(241, 240, 255),
            'text': QColor(0, 0, 0)
        },
        'UDP': {
            'normal': QColor(218, 238, 255),    # Светло-голубой
            'alternate': QColor(228, 248, 255),
            'text': QColor(0, 0, 0)
        },
        'ICMP': {
            'normal': QColor(255, 221, 221),    # Светло-розовый
            'alternate': QColor(255, 231, 231),
            'text': QColor(0, 0, 0)
        },
        
        # DNS и службы имен
        'DNS': {
            'normal': QColor(218, 255, 218),    # Светло-зеленый
            'alternate': QColor(228, 255, 228),
            'text': QColor(0, 0, 0)
        },
        'MDNS': {
            'normal': QColor(218, 255, 218),
            'alternate': QColor(228, 255, 228),
            'text': QColor(0, 0, 0)
        },
        
        # Протоколы маршрутизации
        'ARP': {
            'normal': QColor(250, 240, 215),    # Песочный
            'alternate': QColor(255, 250, 225),
            'text': QColor(0, 0, 0)
        },
        
        # Протоколы управления
        'DHCP': {
            'normal': QColor(255, 255, 210),    # Светло-желтый
            'alternate': QColor(255, 255, 220),
            'text': QColor(0, 0, 0)
        },
        
        # Протоколы передачи файлов
        'FTP': {
            'normal': QColor(255, 200, 200),    # Розовый
            'alternate': QColor(255, 210, 210),
            'text': QColor(0, 0, 0)
        },
        
        # Протоколы удаленного доступа
        'SSH': {
            'normal': QColor(255, 220, 255),    # Светло-пурпурный
            'alternate': QColor(255, 230, 255),
            'text': QColor(0, 0, 0)
        },
        
        # Значение по умолчанию для неизвестных протоколов
        'Unknown': {
            'normal': QColor(255, 255, 255),    # Белый
            'alternate': QColor(245, 245, 245),
            'text': QColor(0, 0, 0)
        }
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Packet Sniffer")
        self.setGeometry(100, 100, 1400, 800)

        self.packet_queue = queue.Queue()
        self.is_capturing = False
        self.packet_count = 0
        self.auto_scroll = True
        self.packets = []
        self.selected_interface = None
        
        # Создаем стек виджетов
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Создаем меню бар
        self.create_menu_bar()
        
        # Создаем toolbar
        self.create_toolbar()
        
        # Создаем оба набора виджетов
        self.create_interface_selection_widgets()
        self.create_capture_widgets()
        
        # Изначально показываем только выбор интерфейса
        self.capture_widgets.hide()
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_table)
        self.timer.start(100)
    
    def create_toolbar(self):
        toolbar = self.addToolBar('Capture Tools')
        toolbar.setMovable(False)
        
        # Создаем кнопки для тулбара
        self.start_button = QPushButton("Start")
   
        self.start_button.clicked.connect(self.start_capture)
        toolbar.addWidget(self.start_button)

        self.pause_button = QPushButton("Pause")
      
        self.pause_button.clicked.connect(self.pause_capture)
        self.pause_button.setEnabled(False)
        toolbar.addWidget(self.pause_button)

        self.restart_button = QPushButton("Restart")
       
        self.restart_button.clicked.connect(self.restart_capture)
        self.restart_button.setEnabled(False)
        toolbar.addWidget(self.restart_button)

        toolbar.addSeparator()

        # Добавляем кнопки изменения размера текста
        self.zoom_in_button = QPushButton('+')
 
        self.zoom_in_button.setToolTip("Increase font size")
        self.zoom_in_button.clicked.connect(self.increase_font_size)
        toolbar.addWidget(self.zoom_in_button)

        self.zoom_out_button = QPushButton('-')
  
        self.zoom_out_button.setToolTip("Decrease font size")
        self.zoom_out_button.clicked.connect(self.decrease_font_size)
        toolbar.addWidget(self.zoom_out_button)

        toolbar.addSeparator()

        self.auto_scroll_checkbox = QCheckBox("Auto Scroll")
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_scroll_checkbox.stateChanged.connect(self.toggle_auto_scroll)
        toolbar.addWidget(self.auto_scroll_checkbox)
        
        toolbar.addSeparator()
        
        self.stats_label = QLabel("Packets: 0")
        toolbar.addWidget(self.stats_label)
    def increase_font_size(self):
        for i in range(self.packet_table.rowCount()):
            current_height = self.packet_table.rowHeight(i)
            self.packet_table.setRowHeight(i, current_height + 2)  # Увеличиваем на 2 пикселя
        
        # Также меняем размер для новых строк
        current_height = self.packet_table.verticalHeader().defaultSectionSize()
        self.packet_table.verticalHeader().setDefaultSectionSize(current_height + 2)
    
    def decrease_font_size(self):
        current_height = self.packet_table.verticalHeader().defaultSectionSize()
        if current_height > 10:  # Минимальная высота строки
            for i in range(self.packet_table.rowCount()):
                current_height = self.packet_table.rowHeight(i)
                self.packet_table.setRowHeight(i, current_height - 2)  # Уменьшаем на 2 пикселя
            
            # Также меняем размер для новых строк
            current_height = self.packet_table.verticalHeader().defaultSectionSize()
            self.packet_table.verticalHeader().setDefaultSectionSize(current_height - 2)

 

    def create_menu_bar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('Файл')
        
        # Действие "Закрыть"
        close_action = file_menu.addAction('Закрыть')
        close_action.triggered.connect(self.show_interface_selection)

    def create_interface_selection_widgets(self):
        self.interface_selection_widget = QWidget()
        layout = QVBoxLayout(self.interface_selection_widget)

        # Header for interface list
        header_label = QLabel("Capture Interfaces")
        header_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(header_label)

        # List widget for interfaces
        self.interface_list = QTableWidget()
        
        self.interface_list.setColumnCount(1)
        self.interface_list.horizontalHeader().hide()
        self.interface_list.verticalHeader().hide()
        self.interface_list.setShowGrid(False)
        self.interface_list.setFrameStyle(0)

        # Add interfaces to the list
        interfaces = self.get_interface_list()
        self.interface_list.setRowCount(len(interfaces))
        for i, iface in enumerate(interfaces):
            item = QTableWidgetItem()
            self.interface_list.setItem(i, 0, item)
            self.interface_list.setRowHeight(i, 50)
            widget = self.create_interface_widget(iface)
            self.interface_list.setCellWidget(i, 0, widget)

        self.interface_list.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.interface_list)
        
        self.main_layout.addWidget(self.interface_selection_widget)

    def create_capture_widgets(self):
        self.capture_widgets = QWidget()
        layout = QVBoxLayout(self.capture_widgets)

        # Main splitter
        self.main_splitter = QSplitter(Qt.Vertical)

        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setShowGrid(False)
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", 
            "Protocol", "Length", "Info"
        ])
        
      
        
        # Настройка заголовков
        header = self.packet_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setHighlightSections(False)
        
        # Настройка выделения
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SingleSelection)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Установка размеров колонок
        self.packet_table.setColumnWidth(0, 100)  # Time
        self.packet_table.setColumnWidth(1, 150)  # Source
        self.packet_table.setColumnWidth(2, 150)  # Destination
        self.packet_table.setColumnWidth(3, 80)   # Protocol
        self.packet_table.setColumnWidth(4, 70)   # Length
        
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
        
        self.main_splitter.addWidget(self.packet_table)

        # Bottom splitter
        bottom_splitter = QSplitter(Qt.Horizontal)
        
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
     
        bottom_splitter.addWidget(self.packet_details)
        
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
      
        bottom_splitter.addWidget(self.hex_view)
        
        self.main_splitter.addWidget(bottom_splitter)
        
        self.main_splitter.setSizes([400, 200])
        bottom_splitter.setSizes([300, 300])
        

        search_layout = QHBoxLayout()
        search_label = QLabel("Filter:")
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter packets (protocol, ip, port)...")
        self.search_bar.textChanged.connect(self.filter_packets)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_bar)
        layout.addLayout(search_layout)

        layout.addWidget(self.main_splitter)
        
        self.main_layout.addWidget(self.capture_widgets)


    def restart_capture(self):
        # Останавливаем текущий захват
        self.stop_capture()
        
        # Очищаем все данные
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.packets.clear()
        while not self.packet_queue.empty():
            self.packet_queue.get()
        self.stats_label.setText("Packets: 0")
        self.packet_details.clear()
        self.hex_view.clear()
        
        # Запускаем новый захват
        self.start_capture()


    def pause_capture(self):
        self.is_capturing = False
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join(timeout=1.0)
        
        # Обновляем состояние кнопок
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.restart_button.setEnabled(True)
        
    def show_interface_selection(self):
        # Останавливаем захват и очищаем данные
        self.stop_capture()
        while not self.packet_queue.empty():
            self.packet_queue.get()
        
        # Очищаем все данные
        self.packet_table.setRowCount(0)
        self.packet_count = 0
        self.packets.clear()
        self.stats_label.setText("Packets: 0")
        self.packet_details.clear()
        self.hex_view.clear()
        self.search_bar.clear()
        
        # Сбрасываем состояние кнопок
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.restart_button.setEnabled(False)
        
        # Переключаем виджеты
        self.capture_widgets.hide()
        self.interface_selection_widget.show()
        
        # Сбрасываем выбранный интерфейс
        self.selected_interface = None

    def get_interface_list(self):
        interfaces = []
        # Get network interfaces with additional information
        for iface, addrs in psutil.net_if_stats().items():
            try:
                addresses = psutil.net_if_addrs()[iface]
                ipv4 = next((addr.address for addr in addresses 
                           if addr.family == socket.AF_INET), "No IPv4")
                status = "Up" if addrs.isup else "Down"
                speed = f"{addrs.speed}Mb/s" if addrs.speed else "Unknown"
                interfaces.append({
                    'name': iface,
                    'ip': ipv4,
                    'status': status,
                    'speed': speed
                })
            except:
                continue
        return interfaces

    def create_interface_widget(self, interface_info):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)

        # Checkbox for interface selection
        checkbox = QCheckBox()
        checkbox.setChecked(False)
        checkbox.stateChanged.connect(
            lambda state, iface=interface_info['name']: 
            self.on_interface_selected(iface, state))
        layout.addWidget(checkbox)

        # Interface information
        info_label = QLabel(
            f"<b>{interface_info['name']}</b><br>"
            f"IP: {interface_info['ip']} | "
            f"Status: {interface_info['status']} | "
            f"Speed: {interface_info['speed']}"
        )
        info_label.setTextFormat(Qt.RichText)
        layout.addWidget(info_label)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def get_interface_name(self, widget):
        # Extract interface name from the widget's label
        label = widget.layout().itemAt(1).widget()
        return label.text().split('<br>')[0].replace('<b>', '').replace('</b>', '')

    def on_interface_selected(self, iface_name, state):
        if state == Qt.Checked:
            self.selected_interface = iface_name
            # Uncheck other interfaces
            for i in range(self.interface_list.rowCount()):
                item_widget = self.interface_list.cellWidget(i, 0)
                if item_widget:
                    checkbox = item_widget.layout().itemAt(0).widget()
                    if checkbox.isChecked() and \
                    self.get_interface_name(item_widget) != iface_name:
                        checkbox.setChecked(False)
            
            # Очищаем все данные перед показом нового интерфейса
            self.packet_table.setRowCount(0)
            self.packet_count = 0
            self.packets.clear()
            while not self.packet_queue.empty():
                self.packet_queue.get()
            self.stats_label.setText("Packets: 0")
            self.packet_details.clear()
            self.hex_view.clear()
            self.search_bar.clear()
            
            # Сбрасываем состояние кнопок
            self.start_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.restart_button.setEnabled(False)
            
            # Переключаем виджеты
            self.interface_selection_widget.hide()
            self.capture_widgets.show()
        else:
            if self.selected_interface == iface_name:
                self.selected_interface = None

    def filter_packets(self):
        search_text = self.search_bar.text().lower()
        
        # Если строка поиска пуста, показываем все пакеты
        if not search_text:
            for row in range(self.packet_table.rowCount()):
                self.packet_table.setRowHidden(row, False)
            return

        # Разбиваем строку поиска на отдельные критерии
        search_terms = search_text.split()

        for row in range(self.packet_table.rowCount()):
            row_visible = True
            row_text = []
            
            # Собираем текст из всех ячеек строки
            for col in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, col)
                if item:
                    row_text.append(item.text().lower())
            
            row_text = ' '.join(row_text)
            
            # Проверяем каждый критерий поиска
            for term in search_terms:
                if term not in row_text:
                    row_visible = False
                    break
            
            self.packet_table.setRowHidden(row, not row_visible)

    def show_packet_details(self):
        selected_rows = self.packet_table.selectedItems()
        if not selected_rows:
            return
        
        row = self.packet_table.currentRow()
        if row >= 0 and row < len(self.packets):
            packet = self.packets[row]
            
            self.packet_details.clear()
            self.hex_view.clear()
            
            details = []
            
            # Frame
            details.append("Frame %d: %d bytes on wire, %d bytes captured" % 
                        (row + 1, len(packet), len(packet)))
            
            # IP
            if IP in packet:
                ip = packet[IP]
                details.append("\nInternet Protocol Version 4, Src: %s, Dst: %s" % (ip.src, ip.dst))
                details.append("    Version: %d" % ip.version)
                details.append("    Header Length: %d bytes" % (ip.ihl * 4))
                details.append("    Total Length: %d" % ip.len)
                details.append("    Identification: 0x%04x (%d)" % (ip.id, ip.id))
                
                # IP Flags
                try:
                    flags_str = ""
                    if hasattr(ip, 'flags'):
                        if ip.flags.DF: flags_str += "DF "
                        if ip.flags.MF: flags_str += "MF "
                        details.append("    Flags: %s" % (flags_str if flags_str else "None"))
                except:
                    details.append("    Flags: None")
                
                details.append("    Fragment offset: %d" % getattr(ip, 'frag', 0))
                details.append("    Time to live: %d" % ip.ttl)
                details.append("    Protocol: %d" % ip.proto)
                details.append("    Header checksum: 0x%04x" % ip.chksum)
                details.append("    Source: %s" % ip.src)
                details.append("    Destination: %s" % ip.dst)
            
            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                details.append("\nTransmission Control Protocol, Src Port: %d, Dst Port: %d" % 
                            (tcp.sport, tcp.dport))
                details.append("    Source Port: %d" % tcp.sport)
                details.append("    Destination Port: %d" % tcp.dport)
                details.append("    Sequence number: %d" % tcp.seq)
                details.append("    Acknowledgment number: %d" % tcp.ack)
                details.append("    Header Length: %d bytes" % (tcp.dataofs * 4))
                
                # TCP Flags - преобразуем в int
                flags_value = int(tcp.flags)
                details.append("    Flags: 0x%03x" % flags_value)
                
                # Проверка отдельных флагов
                if flags_value & 0x02: details.append("        .......1 = SYN")
                if flags_value & 0x10: details.append("        ......1. = ACK")
                if flags_value & 0x01: details.append("        1....... = FIN")
                if flags_value & 0x04: details.append("        ..1..... = RST")
                if flags_value & 0x08: details.append("        ...1.... = PSH")
                if flags_value & 0x20: details.append("        ....1... = URG")
                
                details.append("    Window size value: %d" % tcp.window)
                details.append("    Checksum: 0x%04x" % tcp.chksum)
                
                # TCP payload
                if Raw in packet:
                    try:
                        payload = packet[Raw].load
                        if tcp.dport == 80 or tcp.sport == 80:  # HTTP
                            try:
                                payload_str = payload.decode('utf-8', 'ignore')
                                details.append("\nHypertext Transfer Protocol")
                                for line in payload_str.split('\r\n'):
                                    if line:
                                        details.append("    " + line)
                            except:
                                details.append("\nHTTP Payload (failed to decode)")
                        else:
                            details.append("\nTCP payload (%d bytes)" % len(payload))
                    except:
                        pass
            
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                details.append("\nUser Datagram Protocol, Src Port: %d, Dst Port: %d" % 
                            (udp.sport, udp.dport))
                details.append("    Source Port: %d" % udp.sport)
                details.append("    Destination Port: %d" % udp.dport)
                details.append("    Length: %d" % udp.len)
                details.append("    Checksum: 0x%04x" % udp.chksum)
                
                # DNS
                if DNS in packet:
                    dns = packet[DNS]
                    details.append("\nDomain Name System (%s)" % 
                                ("query" if dns.qr == 0 else "response"))
                    details.append("    Transaction ID: 0x%04x" % dns.id)
                    if dns.qr == 0 and dns.qd:
                        try:
                            qname = dns.qd.qname.decode()
                            details.append("    Queries:")
                            details.append("        %s" % qname)
                        except:
                            details.append("    Queries: <malformed>")
            
            # ICMP
            elif ICMP in packet:
                icmp = packet[ICMP]
                icmp_types = {
                    0: "Echo (ping) reply",
                    8: "Echo (ping) request",
                    3: "Destination unreachable",
                    11: "Time exceeded"
                }
                details.append("\nInternet Control Message Protocol")
                details.append("    Type: %d (%s)" % 
                            (icmp.type, icmp_types.get(icmp.type, "Unknown")))
                details.append("    Code: %d" % icmp.code)
                details.append("    Checksum: 0x%04x" % icmp.chksum)
            
            # ARP
            elif ARP in packet:
                arp = packet[ARP]
                details.append("\nAddress Resolution Protocol")
                details.append("    Hardware type: %d" % arp.hwtype)
                details.append("    Protocol type: 0x%04x" % arp.ptype)
                details.append("    Hardware size: %d" % arp.hwlen)
                details.append("    Protocol size: %d" % arp.plen)
                details.append("    Opcode: %d (%s)" % 
                            (arp.op, "request" if arp.op == 1 else "reply"))
                details.append("    Sender MAC address: %s" % arp.hwsrc)
                details.append("    Sender IP address: %s" % arp.psrc)
                details.append("    Target MAC address: %s" % arp.hwdst)
                details.append("    Target IP address: %s" % arp.pdst)
            
            self.packet_details.setText('\n'.join(details))
            
            # Hex dump
            hex_dump = []
            try:
                data = bytes(Raw(packet))  # преобразуем пакет в байты
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    # Форматируем смещение
                    hex_line = f'{i:04x}  '
                    
                    # Форматируем hex представление
                    hex_values = []
                    for b in chunk:
                        hex_values.append(f'{b:02x}')
                    hex_line += ' '.join(hex_values)
                    
                    # Добавляем пробелы для выравнивания
                    padding = '   ' * (16 - len(chunk))
                    hex_line += padding
                    
                    # Добавляем ASCII представление
                    hex_line += '  '
                    ascii_repr = ''
                    for b in chunk:
                        if 32 <= b <= 126:  # печатаемые ASCII символы
                            ascii_repr += chr(b)
                        else:
                            ascii_repr += '.'
                    hex_line += ascii_repr
                    
                    hex_dump.append(hex_line)
                
                self.hex_view.setPlainText('\n'.join(hex_dump))
            except Exception as e:
                self.hex_view.setPlainText(f"Error creating hex dump: {str(e)}")
             

    def toggle_auto_scroll(self, state):
        self.auto_scroll = state == Qt.Checked

    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
            self.capture_button.setText("Pause Capture")
      
        else:
            self.stop_capture()
            self.capture_button.setText("Resume Capture")
  


    def start_capture(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Warning", "Please select an interface first!")
            return
        
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Обновляем состояние кнопок
        self.start_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.restart_button.setEnabled(True)

    def stop_capture(self):
        self.is_capturing = False
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join(timeout=1.0)
        
        # Сбрасываем состояние кнопок
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.restart_button.setEnabled(False)

    def capture_packets(self):
        while self.is_capturing:
            try:
                sniff(iface=self.selected_interface, 
                      prn=self.process_packet, 
                      store=0, 
                      count=1)
            except Exception as e:
                print(f"Error capturing packet: {e}")

    def process_packet(self, packet):
        try:
            packet_info = self.format_packet_info(packet)
            self.packet_queue.put((packet_info, packet))
        except Exception as e:
            print(f"Error processing packet: {e}")

    def format_packet_info(self, packet):
         
        info = {
            'time': '',
            'src': '',
            'dst': '',
            'protocol': 'Unknown',
            'length': 0,
            'info': ''
        }

        timestamp = time.time()
        info['time'] = time.strftime('%H:%M:%S', time.localtime(timestamp))
        info['time'] += '.{:03d}'.format(int((timestamp * 1000) % 1000))

        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            info['length'] = len(packet)

            if TCP in packet:
                tcp = packet[TCP]
                info['protocol'] = 'TCP'
                flags = []
                
                # Проверка TCP флагов
                if tcp.flags & 0x02: flags.append('SYN')
                if tcp.flags & 0x10: flags.append('ACK')
                if tcp.flags & 0x01: flags.append('FIN')
                if tcp.flags & 0x04: flags.append('RST')
                if tcp.flags & 0x08: flags.append('PSH')
                if tcp.flags & 0x20: flags.append('URG')
                
                # Определение HTTP
                if tcp.dport == 80 or tcp.sport == 80:
                    if Raw in packet:
                        try:
                            raw_data = packet[Raw].load.decode('utf-8', 'ignore')
                            if raw_data.startswith(('GET ', 'POST ', 'HTTP/')):
                                info['protocol'] = 'HTTP'
                                info['info'] = raw_data.split('\r\n')[0]
                        except:
                            pass
                
                if not info['info']:  # если info еще не установлен
                    info['info'] = f"{tcp.sport} → {tcp.dport} [{', '.join(flags)}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

            elif UDP in packet:
                udp = packet[UDP]
                info['protocol'] = 'UDP'
                
                # DNS через UDP
                if udp.dport == 53 or udp.sport == 53:
                    if DNS in packet:
                        info['protocol'] = 'DNS'
                        dns = packet[DNS]
                        if dns.qr == 0:
                            info['info'] = f"Standard query {dns.id:04x} "
                            if dns.qd:
                                try:
                                    info['info'] += f"{dns.qd.qname.decode()}"
                                except:
                                    info['info'] += "Invalid DNS name"
                        else:
                            info['info'] = f"Standard response {dns.id:04x}"
                    else:
                        info['info'] = f"{udp.sport} → {udp.dport} DNS"
                else:
                    info['info'] = f"{udp.sport} → {udp.dport} Len={len(packet[UDP])}"
                
            elif ICMP in packet:
                icmp = packet[ICMP]
                info['protocol'] = 'ICMP'
                icmp_types = {
                    0: 'Echo (ping) reply',
                    8: 'Echo (ping) request',
                    3: 'Destination unreachable',
                    11: 'Time exceeded'
                }
                info['info'] = icmp_types.get(icmp.type, f'Type: {icmp.type}, Code: {icmp.code}')

        elif ARP in packet:
            arp = packet[ARP]
            info['protocol'] = 'ARP'
            info['src'] = arp.hwsrc
            info['dst'] = arp.hwdst
            if arp.op == 1:  # who-has
                info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:  # is-at
                info['info'] = f"{arp.psrc} is at {arp.hwsrc}"

        return info  # Всегда возвращаем info

      

    def update_table(self):
        while not self.packet_queue.empty():
            packet_info, packet = self.packet_queue.get()
            
            self.packet_count += 1
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)

            # Определяем цвета для протокола
            protocol = packet_info['protocol']
            protocol_colors = self.PROTOCOL_COLORS.get(protocol, self.PROTOCOL_COLORS['Unknown'])
            row_color = protocol_colors['alternate'] if row % 2 else protocol_colors['normal']
            text_color = protocol_colors['text']

            # Создаем элементы таблицы
            items = [
                (0, packet_info['time']),
                (1, packet_info['src']),
                (2, packet_info['dst']),
                (3, packet_info['protocol']),
                (4, str(packet_info['length'])),
                (5, packet_info['info'])
            ]

            for col, value in items:
                item = QTableWidgetItem(value)
                item.setBackground(row_color)
                item.setForeground(text_color)
                
                # Выравнивание текста в ячейках
                if col == 4:  # Length column
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                elif col == 3:  # Protocol column
                    item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                else:
                    item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                
                self.packet_table.setItem(row, col, item)

            # Сохраняем пакет для детального просмотра
            self.packets.append(packet)

            self.stats_label.setText(f"Packets: {self.packet_count}")

            if self.auto_scroll:
                self.packet_table.scrollToBottom()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    app.setPalette(DarkPalette())
    window = PacketSniffer()
    pywinstyles.change_header_color(window, color='#181818')  
    pywinstyles.change_title_color(window, color='#ffffff') 
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
