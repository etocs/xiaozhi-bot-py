#!/usr/bin/python
# -*- coding: UTF-8 -*-
import json
import time
import requests
import paho.mqtt.client as mqtt
import threading
import pyaudio
import opuslib
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging
import uuid
import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QTextEdit, QScrollArea, QFrame, QSplitter, QDialog,
                             QMessageBox, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt5.QtGui import QFont, QIcon, QTextCursor

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ChatMessage(QFrame):
    """聊天消息组件加载"""

    def __init__(self, text, is_user=True, emoji=None, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(
            "background-color: #DCF8C6;" if is_user else "background-color: #FFFFFF;"
        )
        layout = QVBoxLayout(self)

        # 如果有表情符号，先显示表情
        if emoji:
            emoji_label = QLabel(emoji)
            emoji_label.setStyleSheet("font-size: 24px;")
            emoji_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(emoji_label)

        # 消息内容
        self.message_label = QLabel(text)
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout.addWidget(self.message_label)
        layout.setContentsMargins(10, 5, 10, 5)


class AudioThread(QThread):
    """音频处理线程"""
    message_received = pyqtSignal(str, bool, str)  # 信号：接收到消息(文本, 是否用户发送, 表情)
    connection_status = pyqtSignal(bool)  # 信号：连接状态(是否连接)
    log_message = pyqtSignal(str)  # 信号：日志消息

    def __init__(self, parent=None):
        super().__init__(parent)
        # 全局变量
        self.OTA_VERSION_URL = 'https://api.tenclass.net/xiaozhi/ota/'
        self.MAC_ADDR = ''
        self.mqtt_info = {}
        self.aes_opus_info = {
            "type": "hello",
            "version": 3,
            "transport": "udp",
            "udp": {
                "server": "120.24.160.13",
                "port": 8884,
                "encryption": "aes-128-ctr",
                "key": "263094c3aa28cb42f3965a1020cb21a7",
                "nonce": "01000000ccba9720b4bc268100000000"
            },
            "audio_params": {
                "format": "opus",
                "sample_rate": 24000,
                "channels": 1,
                "frame_duration": 60
            },
            "session_id": "b23ebfe9"
        }
        self.iot_msg = {
            "session_id": "635aa42d",
            "type": "iot",
            "descriptors": [
                {
                    "name": "Speaker",
                    "description": "当前 AI 机器人的扬声器",
                    "properties": {
                        "volume": {
                            "description": "当前音量值",
                            "type": "number"
                        }
                    },
                    "methods": {
                        "SetVolume": {
                            "description": "设置音量",
                            "parameters": {
                                "volume": {
                                    "description": "0到100之间的整数",
                                    "type": "number"
                                }
                            }
                        }
                    }
                },
                {
                    "name": "Lamp",
                    "description": "一个测试用的灯",
                    "properties": {
                        "power": {
                            "description": "灯是否打开",
                            "type": "boolean"
                        }
                    },
                    "methods": {
                        "TurnOn": {
                            "description": "打开灯",
                            "parameters": {}
                        },
                        "TurnOff": {
                            "description": "关闭灯",
                            "parameters": {}
                        }
                    }
                }
            ]
        }
        self.iot_status_msg = {
            "session_id": "635aa42d",
            "type": "iot",
            "states": [
                {"name": "Speaker", "state": {"volume": 50}},
                {"name": "Lamp", "state": {"power": False}}
            ]
        }
        self.local_sequence = 0
        self.listen_state = None
        self.tts_state = None
        self.key_state = None
        self.audio = None
        self.udp_socket = None
        self.conn_state = False
        self.recv_audio_thread = None
        self.send_audio_thread = None
        self.mqttc = None
        self.is_talking = False  # 是否正在对话
        self.is_running = True  # 线程运行标志
        self.input_device_index = None  # 音频输入设备索引
        self.last_tts_text = ""  # 上一条TTS文本，用于去重
        self.current_emoji = ""  # 当前表情

    def set_mac_address(self, mac_addr):
        """设置MAC地址"""
        self.MAC_ADDR = mac_addr
        self.log_message.emit(f"设置MAC地址为: {self.MAC_ADDR}")

    def set_input_device(self, device_index):
        """设置音频输入设备"""
        self.input_device_index = device_index
        self.log_message.emit(f"设置音频输入设备索引为: {self.input_device_index}")

    def run(self):
        """线程主函数"""
        self.get_ota_version()
        self.audio = pyaudio.PyAudio()

        # 列出可用的音频设备
        self.list_audio_devices()

        # 初始化MQTT客户端
        self.mqttc = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                                 client_id=self.mqtt_info['client_id'])
        self.mqttc.username_pw_set(username=self.mqtt_info['username'], password=self.mqtt_info['password'])
        self.mqttc.tls_set(ca_certs=None, certfile=None, keyfile=None, cert_reqs=mqtt.ssl.CERT_REQUIRED,
                           tls_version=mqtt.ssl.PROTOCOL_TLS, ciphers=None)
        self.mqttc.on_connect = self.on_connect
        self.mqttc.on_disconnect = self.on_disconnect
        self.mqttc.on_message = self.on_message

        try:
            self.log_message.emit(f"正在连接MQTT服务器: {self.mqtt_info['endpoint']}")
            self.mqttc.connect(host=self.mqtt_info['endpoint'], port=8883)
            self.mqttc.loop_start()  # 使用非阻塞模式

            # 发送初始hello消息
            self.start_conversation()

            # 线程主循环
            while self.is_running:
                time.sleep(0.1)

        except Exception as e:
            self.log_message.emit(f"运行错误: {e}")
        finally:
            if self.mqttc:
                self.mqttc.loop_stop()
                self.mqttc.disconnect()
            if self.udp_socket:
                self.udp_socket.close()
            if self.audio:
                self.audio.terminate()

    def stop(self):
        """停止线程"""
        self.is_running = False
        if self.recv_audio_thread and self.recv_audio_thread.is_alive():
            self.recv_audio_thread.join(timeout=1)
        if self.send_audio_thread and self.send_audio_thread.is_alive():
            self.send_audio_thread.join(timeout=1)

    def list_audio_devices(self):
        """列出可用的音频设备"""
        try:
            info = self.audio.get_host_api_info_by_index(0)
            numdevices = info.get('deviceCount')
            self.log_message.emit("可用的音频输入设备:")
            for i in range(0, numdevices):
                device_info = self.audio.get_device_info_by_host_api_device_index(0, i)
                if device_info.get('maxInputChannels') > 0:
                    self.log_message.emit(f"输入设备 {i}: {device_info.get('name')}")
        except Exception as e:
            self.log_message.emit(f"列出音频设备错误: {e}")

    # AES加密
    def aes_ctr_encrypt(self, key, nonce, plaintext):
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    # AES解密
    def aes_ctr_decrypt(self, key, nonce, ciphertext):
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    # 发送音频数据
    def send_audio(self):
        key = self.aes_opus_info['udp']['key']
        nonce = self.aes_opus_info['udp']['nonce']
        server_ip = self.aes_opus_info['udp']['server']
        server_port = self.aes_opus_info['udp']['port']
        encoder = opuslib.Encoder(16000, 1, opuslib.APPLICATION_AUDIO)

        try:
            # 打开麦克风，指定设备索引
            self.log_message.emit(f"打开麦克风，设备索引: {self.input_device_index}")
            mic = self.audio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=16000,
                input=True,
                frames_per_buffer=960,
                input_device_index=self.input_device_index
            )

            self.log_message.emit(f"UDP连接到 {server_ip}:{server_port}")

            while self.is_running:
                if self.listen_state == "stop" and not self.is_talking:
                    time.sleep(0.1)
                    continue

                try:
                    data = mic.read(960)
                    # 计算音量
                    audio_data = [int.from_bytes(data[i:i + 2], byteorder='little', signed=True)
                                  for i in range(0, len(data), 2)]
                    if audio_data:
                        volume = sum(abs(x) for x in audio_data) / len(audio_data)
                        if volume > 100:  # 只记录有意义的音量
                            self.log_message.emit(f"检测到音量: {volume:.2f}")

                    encoded_data = encoder.encode(data, 960)
                    self.local_sequence += 1
                    new_nonce = nonce[0:4] + format(len(encoded_data), '04x') + nonce[8:24] + format(
                        self.local_sequence, '08x')
                    encrypt_encoded_data = self.aes_ctr_encrypt(bytes.fromhex(key), bytes.fromhex(new_nonce),
                                                                bytes(encoded_data))
                    data = bytes.fromhex(new_nonce) + encrypt_encoded_data
                    self.udp_socket.sendto(data, (server_ip, server_port))
                except Exception as e:
                    self.log_message.emit(f"发送音频数据错误: {e}")
                    time.sleep(0.1)
        except Exception as e:
            self.log_message.emit(f"打开麦克风错误: {e}")
        finally:
            self.log_message.emit("UDP连接关闭")
            self.local_sequence = 0
            if 'mic' in locals():
                mic.stop_stream()
                mic.close()

    # 接收音频数据
    def recv_audio(self):
        key = self.aes_opus_info['udp']['key']
        nonce = self.aes_opus_info['udp']['nonce']
        sample_rate = self.aes_opus_info['audio_params']['sample_rate']
        frame_duration = self.aes_opus_info['audio_params']['frame_duration']
        frame_num = int(frame_duration / (1000 / sample_rate))
        decoder = opuslib.Decoder(sample_rate, 1)
        spk = self.audio.open(format=pyaudio.paInt16, channels=1, rate=sample_rate, output=True,
                              frames_per_buffer=frame_num)

        self.log_message.emit(f"UDP连接到 {self.aes_opus_info['udp']['server']}:{self.aes_opus_info['udp']['port']}")
        try:
            while self.is_running:
                try:
                    data, server = self.udp_socket.recvfrom(4096)
                    encrypt_encoded_data = data
                    split_encrypt_encoded_data_nonce = encrypt_encoded_data[:16]
                    split_encrypt_encoded_data = encrypt_encoded_data[16:]
                    decrypt_data = self.aes_ctr_decrypt(bytes.fromhex(key), split_encrypt_encoded_data_nonce,
                                                        split_encrypt_encoded_data)
                    spk.write(decoder.decode(decrypt_data, frame_num))
                except Exception as e:
                    self.log_message.emit(f"接收音频数据错误: {e}")
                    time.sleep(0.1)
        except Exception as e:
            self.log_message.emit(f"接收音频错误: {e}")
        finally:
            self.log_message.emit("UDP接收连接关闭")
            spk.stop_stream()
            spk.close()

    # 获取表情符号
    def get_emoji_for_emotion(self, emotion):
        """根据情绪类型返回对应的表情符号"""
        emoji_map = {
            "funny": "😂",
            "happy": "😊",
            "sad": "😢",
            "angry": "😠",
            "surprised": "😲",
            "confused": "😕",
            "neutral": "😐",
            "thinking": "🤔",
            "love": "❤️",
            "thumbs_up": "👍",
            "thumbs_down": "👎"
        }
        return emoji_map.get(emotion, "")

    # MQTT消息回调
    def on_message(self, client, userdata, message):
        try:
            msg = json.loads(message.payload)
            self.log_message.emit(f"收到消息: {msg}")

            if msg['type'] == 'hello':
                self.aes_opus_info = msg
                self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_socket.connect((msg['udp']['server'], msg['udp']['port']))
                self.iot_msg['session_id'] = msg['session_id']
                self.push_mqtt_msg(self.iot_msg)
                self.iot_status_msg['session_id'] = msg['session_id']
                self.push_mqtt_msg(self.iot_status_msg)

                # 发送连接状态信号
                self.connection_status.emit(True)
                self.conn_state = True
                self.log_message.emit("连接成功，会话ID: " + msg['session_id'])

                if not self.recv_audio_thread or not self.recv_audio_thread.is_alive():
                    self.recv_audio_thread = threading.Thread(target=self.recv_audio)
                    self.recv_audio_thread.daemon = True
                    self.recv_audio_thread.start()

                if not self.send_audio_thread or not self.send_audio_thread.is_alive():
                    self.send_audio_thread = threading.Thread(target=self.send_audio)
                    self.send_audio_thread.daemon = True
                    self.send_audio_thread.start()

                # 自动开始对话
                self.start_listening()

            # 处理表情消息
            elif msg['type'] == 'llm':
                if 'text' in msg and 'emotion' in msg:
                    emoji = self.get_emoji_for_emotion(msg['emotion'])
                    if emoji:
                        self.current_emoji = emoji
                        self.log_message.emit(f"收到表情: {emoji} (情绪: {msg['emotion']})")
                        # 不立即显示表情，等待TTS消息一起显示

            # 处理TTS消息
            elif msg['type'] == 'tts':
                self.tts_state = msg['state']

                # 如果有文本内容，发送到UI显示
                if 'text' in msg and msg['text']:
                    # 只处理开始和结束的消息，避免重复
                    if msg['state'] == 'sentence_start':
                        # 保存当前文本，但不显示
                        self.last_tts_text = msg['text']
                        self.log_message.emit(f"TTS开始: {msg['text']}")

                    elif msg['state'] == 'sentence_end':
                        # 如果与上一条消息相同，则显示
                        if msg['text'] == self.last_tts_text:
                            self.message_received.emit(msg['text'], False, self.current_emoji)
                            self.log_message.emit(f"AI回复: {msg['text']} {self.current_emoji}")
                            # 重置表情和文本
                            self.current_emoji = ""
                            self.last_tts_text = ""

            elif msg['type'] == 'goodbye':
                self.log_message.emit("收到goodbye消息，重置连接状态")
                self.aes_opus_info['session_id'] = None  # 重置 session_id
                self.conn_state = False  # 标记需要重新建立连接

                # 发送连接状态信号
                self.connection_status.emit(False)

                # 关闭 UDP 连接
                if self.udp_socket:
                    self.udp_socket.close()
                    self.udp_socket = None

                self.log_message.emit("UDP连接关闭")

                # 自动重新连接
                time.sleep(1)
                self.start_conversation()
        except Exception as e:
            self.log_message.emit(f"处理消息错误: {e}")

    # MQTT连接回调
    def on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.log_message.emit("MQTT连接成功")
            subscribe_topic = self.mqtt_info['subscribe_topic'].split("/")[
                                  0] + '/p2p/GID_test@@@' + self.MAC_ADDR.replace(':', '_')
            self.log_message.emit(f"订阅主题: {subscribe_topic}")
            client.subscribe(subscribe_topic)

            # 发送连接状态信号
            self.connection_status.emit(True)
        else:
            self.log_message.emit(f"MQTT连接失败，代码 {rc}")
            self.connection_status.emit(False)

    # MQTT断开回调
    def on_disconnect(self, client, userdata, rc, properties=None):
        self.log_message.emit("MQTT断开连接")
        self.connection_status.emit(False)
        if rc != 0:
            self.log_message.emit(f"意外的MQTT断开连接。将自动重连")

    # 推送MQTT消息
    def push_mqtt_msg(self, message):
        if self.mqttc:
            self.mqttc.publish(self.mqtt_info['publish_topic'], json.dumps(message))
            self.log_message.emit(f"发送消息: {message}")

    # 获取OTA版本信息
    def get_ota_version(self):
        header = {
            'Device-Id': self.MAC_ADDR,
            'Content-Type': 'application/json'
        }
        post_data = {
            "flash_size": 16777216,
            "minimum_free_heap_size": 8318916,
            "mac_address": self.MAC_ADDR,
            "chip_model_name": "esp32s3",
            "chip_info": {
                "model": 9,
                "cores": 2,
                "revision": 2,
                "features": 18
            },
            "application": {
                "name": "xiaozhi",
                "version": "0.9.9",
                "compile_time": "Jan 22 2025T20:40:23Z",
                "idf_version": "v5.3.2-dirty",
                "elf_sha256": "22986216df095587c42f8aeb06b239781c68ad8df80321e260556da7fcf5f522"
            },
            "partition_table": [
                {"label": "nvs", "type": 1, "subtype": 2, "address": 36864, "size": 16384},
                {"label": "otadata", "type": 1, "subtype": 0, "address": 53248, "size": 8192},
                {"label": "phy_init", "type": 1, "subtype": 1, "address": 61440, "size": 4096},
                {"label": "model", "type": 1, "subtype": 130, "address": 65536, "size": 983040},
                {"label": "storage", "type": 1, "subtype": 130, "address": 1048576, "size": 1048576},
                {"label": "factory", "type": 0, "subtype": 0, "address": 2097152, "size": 4194304},
                {"label": "ota_0", "type": 0, "subtype": 16, "address": 6291456, "size": 4194304},
                {"label": "ota_1", "type": 0, "subtype": 17, "address": 10485760, "size": 4194304}
            ],
            "ota": {"label": "factory"},
            "board": {
                "type": "bread-compact-wifi",
                "ssid": "mzy",
                "rssi": -58,
                "channel": 6,
                "ip": "192.168.124.38",
                "mac": "cc:ba:97:20:b4:bc"
            }
        }

        try:
            self.log_message.emit(f"获取OTA版本信息，MAC地址: {self.MAC_ADDR}")
            response = requests.post(self.OTA_VERSION_URL, headers=header, data=json.dumps(post_data))
            self.log_message.emit(f"OTA版本响应: {response.text}")
            self.mqtt_info = response.json()['mqtt']
            self.log_message.emit(f"MQTT信息: {self.mqtt_info}")
        except Exception as e:
            self.log_message.emit(f"获取OTA版本错误: {e}")

    # 开始对话
    def start_conversation(self):
        """开始对话，发送hello消息"""
        if not self.conn_state or not self.aes_opus_info.get('session_id'):
            self.conn_state = True
            hello_msg = {
                "type": "hello",
                "version": 3,
                "transport": "udp",
                "audio_params": {
                    "format": "opus",
                    "sample_rate": 16000,
                    "channels": 1,
                    "frame_duration": 60
                }
            }
            if self.mqttc:
                self.push_mqtt_msg(hello_msg)
                self.log_message.emit(f"发送hello消息建立连接: {hello_msg}")

    # 开始监听
    def start_listening(self):
        """开始监听用户语音"""
        self.is_talking = True
        if self.tts_state == "start" or self.tts_state == "sentence_start":
            self.push_mqtt_msg({"type": "abort"})
            self.log_message.emit("发送中止消息")

        if self.aes_opus_info.get('session_id'):
            msg = {
                "session_id": self.aes_opus_info['session_id'],
                "type": "listen",
                "state": "start",
                "mode": "manual"
            }
            self.log_message.emit(f"发送开始监听消息: {msg}")
            self.push_mqtt_msg(msg)
            self.message_received.emit("正在聆听...", True, "")

    # 停止监听
    def stop_listening(self):
        """停止监听用户语音"""
        self.is_talking = False
        if self.aes_opus_info.get('session_id'):
            msg = {
                "session_id": self.aes_opus_info['session_id'],
                "type": "listen",
                "state": "stop"
            }
            self.log_message.emit(f"发送停止监听消息: {msg}")
            self.push_mqtt_msg(msg)


class MacAddressDialog(QDialog):
    """MAC地址输入对话框"""

    def __init__(self, parent=None, saved_mac=None):
        super().__init__(parent)
        self.setWindowTitle("设置MAC地址")
        self.setMinimumWidth(400)

        layout = QVBoxLayout()

        # 说明标签
        info_label = QLabel("请输入设备MAC地址（格式如：92:8A:3D:70:7E:7F）：")
        layout.addWidget(info_label)

        # MAC地址输入框
        self.mac_input = QLineEdit()
        if saved_mac:
            self.mac_input.setText(saved_mac)
        else:
            # 尝试获取系统MAC地址作为默认值
            mac = self.get_mac_address()
            self.mac_input.setText(mac)
        layout.addWidget(self.mac_input)

        # 按钮布局
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("确定")
        self.ok_button.clicked.connect(self.accept)
        button_layout.addWidget(self.ok_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def get_mac_address(self):
        """获取系统MAC地址"""
        try:
            mac_int = uuid.getnode()
            mac_hex = "{:012x}".format(mac_int)
            mac_address = ":".join([mac_hex[i:i + 2] for i in range(0, 12, 2)]).lower()
            return mac_address
        except:
            return "00:00:00:00:00:00"

    def get_mac(self):
        """获取用户输入的MAC地址"""
        return self.mac_input.text()


class MainWindow(QMainWindow):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("小智语音助手")
        self.setMinimumSize(800, 600)

        # 加载设置
        self.settings = QSettings("XiaozhiGUI", "Settings")
        saved_mac = self.settings.value("mac_address", "")
        saved_device = self.settings.value("input_device", None)
        if saved_device:
            try:
                saved_device = int(saved_device)
            except:
                saved_device = None

        # 如果没有保存的MAC地址，显示对话框
        if not saved_mac:
            dialog = MacAddressDialog(self)
            if dialog.exec_():
                saved_mac = dialog.get_mac()
                self.settings.setValue("mac_address", saved_mac)

        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)

        # 状态栏
        status_layout = QHBoxLayout()
        self.status_label = QLabel("未连接")
        self.status_label.setStyleSheet("color: red;")
        status_layout.addWidget(self.status_label)

        # 设备选择
        device_label = QLabel("音频输入设备:")
        status_layout.addWidget(device_label)
        self.device_combo = QComboBox()
        status_layout.addWidget(self.device_combo)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self.refresh_devices)
        status_layout.addWidget(self.refresh_button)

        main_layout.addLayout(status_layout)

        # 创建分割器
        splitter = QSplitter(Qt.Vertical)

        # 聊天记录区域
        self.chat_area = QScrollArea()
        self.chat_area.setWidgetResizable(True)
        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_widget)
        self.chat_layout.addStretch()
        self.chat_area.setWidget(self.chat_widget)
        splitter.addWidget(self.chat_area)

        # 日志区域
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        splitter.addWidget(self.log_text)

        # 设置分割器初始大小
        splitter.setSizes([400, 200])
        main_layout.addWidget(splitter)

        # 控制按钮区域
        control_layout = QHBoxLayout()

        self.talk_button = QPushButton("按住说话")
        self.talk_button.setCheckable(True)
        self.talk_button.pressed.connect(self.on_talk_pressed)
        self.talk_button.released.connect(self.on_talk_released)
        control_layout.addWidget(self.talk_button)

        self.settings_button = QPushButton("设置")
        self.settings_button.clicked.connect(self.show_settings)
        control_layout.addWidget(self.settings_button)

        main_layout.addLayout(control_layout)

        # 创建音频处理线程
        self.audio_thread = AudioThread()
        self.audio_thread.set_mac_address(saved_mac)
        self.audio_thread.message_received.connect(self.add_message)
        self.audio_thread.connection_status.connect(self.update_connection_status)
        self.audio_thread.log_message.connect(self.add_log)

        # 初始化设备列表
        self.refresh_devices()

        # 如果有保存的设备，设置它
        if saved_device is not None:
            index = self.device_combo.findData(saved_device)
            if index >= 0:
                self.device_combo.setCurrentIndex(index)
                self.audio_thread.set_input_device(saved_device)

        # 设备选择变更事件
        self.device_combo.currentIndexChanged.connect(self.on_device_changed)

        # 启动音频线程
        self.audio_thread.start()

        # 添加欢迎消息
        self.add_message("欢迎使用小智语音助手！请按住"'按住说话'"按钮开始对话。", False, "")

    def closeEvent(self, event):
        """窗口关闭事件"""
        self.audio_thread.stop()
        self.audio_thread.wait()
        event.accept()

    def on_talk_pressed(self):
        """按下说话按钮"""
        self.talk_button.setText("正在说话...")
        self.audio_thread.start_listening()

    def on_talk_released(self):
        """释放说话按钮"""
        self.talk_button.setText("按住说话")
        self.audio_thread.stop_listening()

    def add_message(self, text, is_user=True, emoji=""):
        """添加消息到聊天区域"""
        message = ChatMessage(text, is_user, emoji)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, message)
        # 滚动到底部
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )

    def add_log(self, text):
        """添加日志消息"""
        self.log_text.append(text)
        # 滚动到底部
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )

    def update_connection_status(self, connected):
        """更新连接状态"""
        if connected:
            self.status_label.setText("已连接")
            self.status_label.setStyleSheet("color: green;")
        else:
            self.status_label.setText("未连接")
            self.status_label.setStyleSheet("color: red;")

    def refresh_devices(self):
        """刷新音频设备列表"""
        self.device_combo.clear()

        try:
            audio = pyaudio.PyAudio()
            info = audio.get_host_api_info_by_index(0)
            numdevices = info.get('deviceCount')

            self.add_log("可用的音频输入设备:")
            for i in range(0, numdevices):
                device_info = audio.get_device_info_by_host_api_device_index(0, i)
                if device_info.get('maxInputChannels') > 0:
                    device_name = device_info.get('name')
                    self.device_combo.addItem(f"{i}: {device_name}", i)
                    self.add_log(f"输入设备 {i}: {device_name}")

            audio.terminate()

            if self.device_combo.count() == 0:
                self.add_log("未找到输入设备!")
                self.talk_button.setEnabled(False)
            else:
                self.talk_button.setEnabled(True)

        except Exception as e:
            self.add_log(f"刷新设备列表错误: {e}")

    def on_device_changed(self, index):
        """设备选择变更事件"""
        if index >= 0:
            device_index = self.device_combo.itemData(index)
            self.add_log(f"选择音频输入设备: {device_index}")
            self.audio_thread.set_input_device(device_index)
            self.settings.setValue("input_device", device_index)

    def show_settings(self):
        """显示设置对话框"""
        saved_mac = self.settings.value("mac_address", "")
        dialog = MacAddressDialog(self, saved_mac)
        if dialog.exec_():
            new_mac = dialog.get_mac()
            if new_mac != saved_mac:
                self.settings.setValue("mac_address", new_mac)
                QMessageBox.information(self, "设置已更新",
                                        "MAC地址已更新，请重启应用以应用新设置。")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
