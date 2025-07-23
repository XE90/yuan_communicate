#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import socket
import threading
import os
import base64
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout,QDialog, 
                               QHBoxLayout, QWidget, QTextEdit, QLineEdit, 
                               QPushButton, QLabel, QComboBox, QSplitter,
                               QListWidget, QFrame, QFileDialog, QProgressBar)
from PySide6.QtCore import Qt, Signal, QObject, QSize, QByteArray, QThread
from PySide6.QtGui import QTextCursor, QPixmap, QTextDocument, QTextImageFormat, QColor
import subprocess
import platform

'''
tool_name = 'yuan_communicate'
tool_ver = '1.0.3'
release_date = '2025.07.23'
author = 'Gavin.Xie'
'''

def run_cmd(cmd):
    out, err = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding='gbk', shell=True).communicate()
    return out, err

def get_os_type():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    else:
        return "Other (e.g., macOS)"

class Communicate(QObject):
    message_received = Signal(str, str, str, str)  # 参数: sender, message, from_ip, to_ip
    file_received = Signal(str, str, str, bytes)  # 文件名, 发送方IP, 接收方IP, 文件内容
    progress_update = Signal(int)  # 文件传输进度

class NetworkThread(threading.Thread):
    def __init__(self, port, comm, local_ip):
        super().__init__()
        self.port = port
        self.comm = comm
        self.local_ip = local_ip
        self.running = True
        
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', self.port))
            s.listen()
            while self.running:
                conn, addr = s.accept()
                with conn:
                    # 接收消息类型标识
                    msg_type = conn.recv(1)
                    if not msg_type:
                        continue
                    
                    if msg_type == b'T':  # 文本消息
                        # print(f"接收到文本消息类型标识 from {addr}")
                        
                        # 先读取消息长度(4字节)
                        try:
                            msg_len_bytes = conn.recv(4)
                            if not msg_len_bytes or len(msg_len_bytes) != 4:
                                continue
                            msg_len = int.from_bytes(msg_len_bytes, byteorder='big')
                            # print(f"消息长度: {msg_len}")
                            
                            # 读取消息内容
                            data = bytearray()
                            remaining = msg_len
                            while remaining > 0:
                                chunk = conn.recv(min(4096, remaining))
                                if not chunk:
                                    break
                                data.extend(chunk)
                                remaining -= len(chunk)
                            
                            if remaining == 0:
                                message = data.decode('utf-8')
                                # print(f"接收到消息: {message}")
                                # self.comm.message_received.emit(addr[0], message, addr[0], self.local_ip)
                                self.comm.message_received.emit("对方", message, addr[0], self.local_ip)
                            else:
                                print("消息接收不完整")
                        
                        except Exception as e:
                            print(f"接收文本消息错误: {str(e)}")
                            self.comm.message_received.emit(f"接收错误: {str(e)}", "系统", self.local_ip)
                    elif msg_type == b'F':  # 文件消息
                        # 接收文件名长度
                        name_len = int.from_bytes(conn.recv(4), byteorder='big')
                        # 接收文件名
                        filename = conn.recv(name_len).decode('utf-8')
                        # 接收文件大小
                        file_size = int.from_bytes(conn.recv(8), byteorder='big')
                        # 接收文件内容
                        file_data = bytearray()
                        received = 0
                        while received < file_size:
                            chunk = conn.recv(min(4096, file_size - received))
                            if not chunk:
                                break
                            file_data.extend(chunk)
                            received += len(chunk)
                            # 更新进度
                            progress = int((received / file_size) * 100)
                            self.comm.progress_update.emit(progress)
                        
                        if len(file_data) == file_size:
                            self.comm.file_received.emit(filename, addr[0], self.local_ip, bytes(file_data))
    
    def stop(self):
        self.running = False
        # 创建一个临时连接来解除阻塞
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.connect(('localhost', self.port))
        temp_socket.close()

class WorkerThread(QThread):
    output_signal = Signal(str, str)
    finished_signal = Signal(int)

    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args

    def check_net_connect_status(self):
        os_type = get_os_type()
        if os_type == 'Windows':
            cmd = f'ping www.baidu.com'
        elif os_type == 'Linux':
            cmd = f'ping -c 4 www.baidu.com'
        else:
            msg = fr'Not support os_type: {os_type}'
            self.output_signal.emit(msg, "red")
            return
        self.output_signal.emit(f'{cmd} ...', "black")
        out, err = run_cmd(cmd)
        if err:
            msg = '执行ping命令发送错误'
            self.output_signal.emit(err, "black")
            self.output_signal.emit(msg, "red")
        else:
            self.output_signal.emit(out, "black")
            if os_type == 'Windows' and ('0% 丢失' in out or fr'0% Lost' in out):
                msg = '连接到Internet网络成功！'
                self.output_signal.emit(msg, "green")
            elif os_type == 'Linux' and '0% packet loss' in out:
                msg = '连接到Internet网络成功！'
                self.output_signal.emit(msg, "green")
            else:
                msg = '无法连通到Internet网络， 请检查！'
                self.output_signal.emit(msg, "red")

    def run(self):
        try:
            if self.operation == "check_net_status":
                # msg = 'Uninstall software ...'
                # self.output_signal.emit(msg, "black")
                print(f'start do ping method')
                self.check_net_connect_status()
        except Exception as e:
            self.output_signal.emit(f"Error: {str(e)}", "red")

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("元通信")
        self.setGeometry(50, 50, 800, 500)
        
        # 通信对象
        self.comm = Communicate()

        # 使用Qt.QueuedConnection确保信号跨线程安全
        self.comm.message_received.connect(self.display_message, Qt.QueuedConnection)
        self.comm.file_received.connect(self.display_file, Qt.QueuedConnection)
        self.comm.progress_update.connect(self.update_progress, Qt.QueuedConnection)
        
        # 网络线程
        self.network_thread = None
        self.current_ip = None
        self.current_file = None
        self.file_sending = False
        
        # 创建UI
        self.init_ui()
        self.apply_styles()
        self.receive_area.setHtml("""
            <html>
            <body style='
                font-family: Arial;
                font-size: 12px;
                margin: 0;
                padding: 0;
            '></body>
            </html>
            """)

    def init_ui(self):
        # 主布局
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 主分割器 (消息区域 + 底部区域)
        main_splitter = QSplitter(Qt.Vertical)
        
        # 消息显示区域
        self.receive_area = QTextEdit()
        self.receive_area.setReadOnly(True)
        self.receive_area.setAcceptRichText(True)
        
        # 底部区域
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        # 配置区域
        config_group = QWidget()
        config_layout = QVBoxLayout(config_group)
        config_layout.setContentsMargins(10, 10, 10, 10)

        self.check_net_status = QPushButton('检查网络连接')
        self.check_net_status.clicked.connect(self.show_net_connect_status)
        config_layout.addWidget(self.check_net_status)
        
        self.ip_combo = QComboBox()
        self.ip_combo.addItems(self.get_local_ips())
        self.ip_combo.setEditable(True)
        
        self.port_input = QLineEdit("8080")
        self.port_input.setFixedWidth(80)
        
        self.start_button = QPushButton("启动服务器")
        self.start_button.clicked.connect(self.toggle_server)
        self.start_button.setFixedHeight(30)
        
        config_layout.addWidget(QLabel("本地IP:"))
        config_layout.addWidget(self.ip_combo)
        config_layout.addWidget(QLabel("端口:"))
        config_layout.addWidget(self.port_input)
        config_layout.addWidget(self.start_button)
        config_layout.addStretch()

        self.target_ip = QLineEdit()
        config_layout.addWidget(QLabel("目标IP:"))
        self.target_ip.setPlaceholderText("目标IP")
        config_layout.addWidget(self.target_ip)

        self.target_port = QLineEdit("8080")
        self.target_port.setFixedWidth(80)
        config_layout.addWidget(QLabel("目标端口:"))
        config_layout.addWidget(self.target_port)
        
        # 文件传输进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        config_layout.addWidget(self.progress_bar)
        
        # 发送区域
        send_group = QWidget()
        send_layout = QHBoxLayout(send_group)
        send_layout.setContentsMargins(5, 10, 10, 10)
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("输入消息...")
        self.message_input.setMinimumHeight(100)
        self.message_input.setLineWrapMode(QTextEdit.WidgetWidth)
        self.message_input.keyPressEvent = self.handle_key_press
        
        # 按钮区域
        button_group = QWidget()
        button_layout = QVBoxLayout(button_group)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(5)
        
        self.send_button = QPushButton("发送")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setFixedWidth(80)
        
        self.file_button = QPushButton("发送文件")
        self.file_button.clicked.connect(self.select_file)
        self.file_button.setFixedWidth(80)
        
        self.image_button = QPushButton("发送图片")
        self.image_button.clicked.connect(self.select_image)
        self.image_button.setFixedWidth(80)
        
        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.file_button)
        button_layout.addWidget(self.image_button)
        button_layout.addStretch()
        
        send_layout.addWidget(self.message_input)
        send_layout.addWidget(button_group)
        
        # 添加到底部布局
        bottom_layout.addWidget(send_group)
        
        # 设置分割器
        main_splitter.addWidget(self.receive_area)
        main_splitter.addWidget(bottom_widget)
        main_splitter.setStretchFactor(0, 4)
        main_splitter.setStretchFactor(1, 1)
        
        # 左侧导航栏
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # 联系人列表
        self.contact_list = QListWidget()
        self.contact_list.addItems(["本地连接", "网络连接"])
        self.contact_list.setCurrentRow(0)
        left_layout.addWidget(self.contact_list)
        left_layout.addStretch()

        left_layout.addWidget(config_group)
        
        # 主分割器 (左侧导航栏 + 右侧主区域)
        content_splitter = QSplitter()
        content_splitter.addWidget(left_widget)
        content_splitter.addWidget(main_splitter)
        content_splitter.setStretchFactor(1, 7)
        content_splitter.setSizes([150, 650])
        
        # 添加到主布局
        main_layout.addWidget(content_splitter)
        self.setCentralWidget(main_widget)

    def show_net_connect_status(self):
        """显示网络连接"""
        dialog = QDialog(self)
        dialog.setWindowTitle("网络连接状况")
        dialog.setFixedSize(400, 300)
        layout = QVBoxLayout(dialog)
        
        # 添加说明标签
        label = QLabel("点击’检测‘按钮开始检查网络状况 ...")
        layout.addWidget(label)
        
        # 添加文本框
        self.net_status_output_text = QTextEdit()
        self.net_status_output_text.setReadOnly(True)
        layout.addWidget(self.net_status_output_text)
        
        # 添加按钮布局
        button_layout = QHBoxLayout()

        # 检查按钮
        check_btn = QPushButton("检测")
        check_btn.clicked.connect(self.start_check_net_thread)
        # check_btn.setStyleSheet(f"""
        #     QPushButton {{
        #         background: green;
        #         color: white;
        #         border-radius: 5px;
        #         padding: 5px 10px;
        #     }}
        #     QPushButton:hover {{
        #         background: white;
        #         color: green;
        #         border: 1px solid green;
        #     }}
        # """)
    
        # 取消按钮
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(dialog.reject)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: #ccc;
                color: black;
                border-radius: 5px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background: #aaa;
            }
        """)
        button_layout.addWidget(check_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.exec()
        

    def start_check_net_thread(self):
        self.check_net_thread = WorkerThread("check_net_status")
        self.check_net_thread.output_signal.connect(self.append_output)
        self.check_net_thread.finished_signal.connect(self.check_net_thread.deleteLater)
        self.check_net_thread.start()

    def append_output(self, text, color):
        """Append text to the output area with specified color"""
        self.net_status_output_text.setTextColor(QColor(color))
        self.net_status_output_text.append(text)
        self.net_status_output_text.moveCursor(QTextCursor.End)
        
    def apply_styles(self):
        self.setStyleSheet("""
            /* 主窗口样式 */
            QMainWindow {
                background-color: #f5f5f5;
            }
            
            /* 左侧导航栏样式 */
            QWidget {
                border: none;
            }
            
            QListWidget {
                background-color: #f0f0f0;
                border: none;
                font-size: 14px;
            }
            
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #e0e0e0;
            }
            
            QListWidget::item:hover {
                background-color: #e0e0e0;
            }
            
            QListWidget::item:selected {
                background-color: #d0d0d0;
                color: #000;
            }
            
            /* 配置区域样式 */
            QLabel {
                font-size: 12px;
                color: #666;
            }
            
            QLineEdit, QComboBox {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                font-size: 12px;
                min-height: 25px;
            }
            
            QPushButton {
                background-color: #45a049;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
            }
            
            QPushButton:hover {
                background-color: #45a049;
            }
            
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            
            /* 消息区域样式 */
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                font-size: 12px;
            }
            
            QTextEdit:focus {
                border: 1px solid #4CAF50;
            }
            
            /* 分割器样式 */
            QSplitter::handle {
                background-color: #e0e0e0;
                width: 1px;
            }
            
            /* 进度条样式 */
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 4px;
                text-align: center;
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
        """)
        
    def get_local_ips(self):
        """获取本地IP地址"""
        ips = ["127.0.0.1"]
        try:
            hostname = socket.gethostname()
            ips.extend(socket.gethostbyname_ex(hostname)[2])
        except:
            pass
        return ips
        
    def toggle_server(self):
        """启动/停止服务器"""
        if self.network_thread and self.network_thread.is_alive():
            self.stop_server()
            self.start_button.setText("启动服务器")
            self.start_button.setStyleSheet("background-color: #4CAF50;")
        else:
            self.current_ip = self.ip_combo.currentText()
            self.start_server()
            self.start_button.setText("停止服务器")
            self.start_button.setStyleSheet("background-color: #f44336;")
            
    def start_server(self):
        """启动服务器线程"""
        try:
            port = int(self.port_input.text())
            self.network_thread = NetworkThread(port, self.comm, self.current_ip)
            self.network_thread.start()
            self.display_message("系统", f"服务器已启动，监听端口 {port}", self.current_ip, "0.0.0.0")
            self.receive_area.append("")
        except ValueError:
            self.display_message("系统", "请输入有效的端口号", self.current_ip, "0.0.0.0")
            
    def stop_server(self):
        """停止服务器线程"""
        if self.network_thread:
            self.network_thread.stop()
            self.network_thread.join()
            self.display_message("系统", "服务器已停止", self.current_ip, "0.0.0.0")

    def handle_key_press(self, event):
        """处理多行输入框的按键事件"""
        if event.key() == Qt.Key_Return and not event.modifiers() & Qt.ShiftModifier:
            self.send_message()
        else:
            QTextEdit.keyPressEvent(self.message_input, event)
            
    def send_message(self): 
        """发送消息（适配QTextEdit版本）"""
        ip = self.target_ip.text()
        port_text = self.target_port.text()
        message = self.message_input.toPlainText().strip()
        
        if not ip or not port_text or not message:
            return
            
        try:
            port = int(port_text)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                # 先发送消息类型标识
                s.sendall(b'T')  # 'T'表示文本消息
                
                # 发送消息长度(4字节)
                msg_bytes = message.encode('utf-8')
                s.sendall(len(msg_bytes).to_bytes(4, byteorder='big'))
                
                # 发送消息内容
                s.sendall(msg_bytes)
                
                # print(f"已发送消息到 {ip}:{port}: {message}")
                self.display_message("我", message, self.current_ip, ip)
                self.message_input.clear()
        except Exception as e:
            print(f"发送消息失败: {str(e)}")
            self.display_message("系统", f"发送失败: {str(e)}", self.current_ip, ip)
    
    def select_file(self):
        """选择要发送的文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*.*)")
        if file_path:
            self.send_file(file_path)
    
    def select_image(self):
        """选择要发送的图片"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择图片", "", "图片文件 (*.png *.jpg *.jpeg *.bmp *.gif)")
        if file_path:
            self.send_file(file_path, is_image=True)
    
    def send_file(self, file_path, is_image=False):
        """发送文件"""
        ip = self.target_ip.text()
        port_text = self.target_port.text()
        
        if not ip or not port_text:
            return
            
        try:
            port = int(port_text)
            filename = os.path.basename(file_path)
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.file_sending = True
            
            # 在新线程中发送文件，避免阻塞UI
            threading.Thread(target=self._send_file_thread, args=(ip, port, filename, file_data, is_image)).start()
            
        except Exception as e:
            print(f"文件操作错误: {str(e)}")
            self.display_message("系统", f"文件发送失败: {str(e)}", self.current_ip, "0.0.0.0")
            self.progress_bar.setVisible(False)
    
    def _send_file_thread(self, ip, port, filename, file_data, is_image):
        """在单独线程中发送文件"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                # 发送消息类型标识
                s.sendall(b'F')
                # 发送文件名长度和文件名
                s.sendall(len(filename).to_bytes(4, byteorder='big'))
                s.sendall(filename.encode('utf-8'))
                # 发送文件大小
                s.sendall(len(file_data).to_bytes(8, byteorder='big'))
                # 发送文件内容
                sent = 0
                chunk_size = 4096
                last_progress = -1

                while sent < len(file_data):
                    chunk = file_data[sent:sent+chunk_size]
                    s.sendall(chunk)
                    sent += len(chunk)
                    # 更新进度 - 只在进度变化时发射信号
                    current_progress = int((sent / len(file_data)) * 100)
                    if current_progress != last_progress:
                        self.comm.progress_update.emit(current_progress)
                        last_progress = current_progress
                    # 更新进度 - 通过信号通知主线程
                    # progress = int((sent / len(file_data))) * 100
                    # progress = int((sent / len(file_data)) * 100)  # 先计算比例再取整
                    # self.comm.progress_update.emit(progress)
                
                # 通知主线程发送完成
                if is_image:
                    self.comm.message_received.emit("我", f"[图片: {filename}]", self.current_ip, ip)
                else:
                    self.comm.message_received.emit("我", f"[文件: {filename}]", self.current_ip, ip)
                    
        except Exception as e:
            # 错误处理也通过信号通知主线程
            self.comm.message_received.emit("系统", f"文件发送失败: {str(e)}", self.current_ip, ip)
        finally:
            # self.comm.progress_update.emit(0)  # 重置进度条
            self.comm.progress_update.emit(100)  # 传输完成
    
    def update_progress(self, value):
        """更新进度条 - 确保在主线程执行"""
        if QThread.currentThread() != self.thread():
            print("警告: 尝试在非主线程更新进度条")
            return
        """更新进度条"""
        self.progress_bar.setValue(value)
        if value >= 100:
            self.progress_bar.setVisible(False)
    
    def display_file(self, filename, from_ip, to_ip, file_data):
        """显示接收到的文件"""
        try:
            # 如果是图片，直接显示
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
                # 将图片数据转换为base64编码
                image_base64 = base64.b64encode(file_data).decode('ascii')
                self.display_image(filename, from_ip, to_ip, image_base64)
            else:
                # 保存文件到本地
                save_path = os.path.join(os.getcwd(), filename)
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                self.display_message(from_ip, f"[文件已接收: {filename}]", from_ip, to_ip)
        except Exception as e:
            self.display_message("系统", f"文件处理失败: {str(e)}", from_ip, to_ip)
    
    def display_image(self, filename, from_ip, to_ip, image_base64):
        """在消息区域显示图片"""
        cursor = self.receive_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if from_ip == self.current_ip:  # 自己发送的图片
            html = f"""
            <table width='100%' cellspacing='0' cellpadding='0' style='margin:8px 0;'>
                <tr>
                    <td align='right' style='padding-right:10px;'>
                        <span style='font-size:11px; color:#666;'>{time_str} 发送给: {to_ip}</span>
                    </td>
                </tr>
                <tr>
                    <td align='right' style='padding-right:10px; padding-top:4px;'>
                        <div style='
                            background:#dcf8c6;
                            border-radius:18px;
                            padding:8px 12px;
                            display:inline-block;
                            max-width:70%;
                            word-wrap:break-word;
                        '>
                            <img src='data:image/png;base64,{image_base64}' style='max-width:300px; max-height:300px;'/>
                            <div style='font-size:11px; color:#666;'>{filename}</div>
                        </div>
                    </td>
                </tr>
            </table>
            """
        else:  # 接收到的图片
            html = f"""
            <table width='100%' cellspacing='0' cellpadding='0' style='margin:8px 0;'>
                <tr>
                    <td style='padding-left:10px;'>
                        <span style='font-size:11px; color:#666;'>{time_str} 来自: {from_ip}</span>
                    </td>
                </tr>
                <tr>
                    <td style='padding-left:10px; padding-top:4px;'>
                        <div style='
                            background:#e9e9e9;
                            border-radius:18px;
                            padding:8px 12px;
                            display:inline-block;
                            max-width:70%;
                            word-wrap:break-word;
                        '>
                            <img src='data:image/png;base64,{image_base64}' style='max-width:300px; max-height:300px;'/>
                            <div style='font-size:11px; color:#666;'>{filename}</div>
                        </div>
                    </td>
                </tr>
            </table>
            """
        
        cursor.insertHtml("<br>" + html)
        self.receive_area.setTextCursor(cursor)
        self.receive_area.ensureCursorVisible()
            
    
    def display_message(self, sender, message, from_ip, to_ip):
        """显示消息 - 使用表格确保严格分行"""
        """显示消息 - 确保在主线程执行"""
        # 检查当前线程是否是主线程
        if QThread.currentThread() != self.thread():
            print("警告: 尝试在非主线程显示消息")
            return
        cursor = self.receive_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # time_str = datetime.now().strftime("%H:%M")
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if sender == "我":
            # 自己发送的消息样式
            html = f"""
            <table width='100%' cellspacing='0' cellpadding='0' style='margin:8px 0;'>
                <tr>
                    <td align='right' style='padding-right:10px;'>
                        <span style='font-size:11px; color:#666;'>{time_str} 发送给: {to_ip}</span>
                    </td>
                </tr>
                <tr>
                    <td align='right' style='padding-right:10px; padding-top:4px;'>
                        <span style='
                            background:#dcf8c6;
                            border-radius:18px;
                            padding:8px 12px;
                            display:inline-block;
                            max-width:70%;
                            word-wrap:break-word;
                        '>{message}</span>
                    </td>
                </tr>
            </table>
            """
        elif sender == "系统":
            # 系统消息样式
            html = f"""
            <table width='100%' cellspacing='0' cellpadding='0' style='margin:8px 0;'>
                <tr>
                    <td align='center'>
                        <span style='font-size:11px; color:#999;'>{time_str}</span>
                    </td>
                </tr>
                <tr>
                    <td align='center' style='padding-top:4px;'>
                        <span style='font-size:11px; color:#999;'>{message}</span>
                    </td>
                </tr>
            </table>
            """
        else:
            # 对方发送的消息样式
            html = f"""
            <table width='100%' cellspacing='0' cellpadding='0' style='margin:8px 0;'>
                <tr>
                    <td style='padding-left:10px;'>
                        <span style='font-size:11px; color:#666;'>{time_str} 来自: {from_ip}</span>
                    </td>
                </tr>
                <tr>
                    <td style='padding-left:10px; padding-top:4px;'>
                        <span style='
                            background:#e9e9e9;
                            border-radius:18px;
                            padding:8px 12px;
                            display:inline-block;
                            max-width:70%;
                            word-wrap:break-word;
                        '>{message}</span>
                    </td>
                </tr>
            </table>
            """
        
        cursor.insertHtml("<br>" + html)
        self.receive_area.setTextCursor(cursor)
        self.receive_area.ensureCursorVisible()
            
    def closeEvent(self, event):
        """窗口关闭事件"""
        self.stop_server()
        super().closeEvent(event)

def main():
    def handle_exception(exc_type, exc_value, exc_traceback):
        import traceback
        print("".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
        QApplication.quit()
    
    sys.excepthook = handle_exception
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()