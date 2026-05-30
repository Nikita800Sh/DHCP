"""
Базовый DHCP-сервер на Python 3 с использованием Scapy.

ИНСТРУКЦИЯ ПО НАСТРОЙКЕ И ЗАПУСКУ:

1. Установка зависимостей:
   - Python: Убедитесь, что установлен Python 3.
   - Scapy: Установите через pip -> pip install scapy
   - Linux: Установите пакет libpcap (например, sudo apt install libpcap-dev).
   - Windows: Установите Npcap (скачать с https://npcap.com/). При установке ОБЯЗАТЕЛЬНО
     поставьте галочку "Install Npcap in WinPcap API-compatible Mode".

2. Настройка виртуальной сети (VirtualBox / VMware):
   - Чтобы сервер корректно раздавал адреса, установите тип сети для виртуальных машин
     в "Host-Only Adapter" (Виртуальный адаптер хоста) или "Internal Network" (Внутренняя сеть).
   - ВАЖНО: Отключите встроенный DHCP-сервер гипервизора! В VirtualBox это делается
     в меню "File -> Tools -> Network Manager", выберите ваш Host-Only адаптер,
     перейдите во вкладку "DHCP Server" и снимите галочку "Enable Server".

3. Отключение встроенного DHCP-клиента на интерфейсе сервера:
   - Чтобы ваша ОС не конфликтовала с вашим же скриптом, задайте статический IP-адрес
     для сетевого интерфейса, на котором будет работать этот скрипт.
   - Linux:
     Остановите сетевой менеджер для этого интерфейса или используйте команду освобождения:
     sudo dhclient -r <имя_интерфейса>
   - Windows:
     Откройте "Сетевые подключения" (ncpa.cpl) -> Свойства адаптера -> IP версии 4 (TCP/IPv4) ->
     "Использовать следующий IP-адрес". Укажите IP, который вы зададите в SERVER_IP ниже.

4. Как узнать имя сетевого интерфейса (для переменной INTERFACE):
   - Linux: Выполните команду ip a. Имя будет выглядеть как "eth0", "enp0s3" и т.д.
   - Windows: Выполните команду ipconfig /all. Scapy в Windows может принимать имя
     виртуального адаптера, либо его описание (например, "VirtualBox Host-Only Ethernet Adapter").
     Вы также можете запустить python -c "from scapy.all import get_windows_if_list; print([i['name'] for i in get_windows_if_list()])"
     для получения точного списка имен, понятных Scapy.

5. Запуск скрипта:
   - Скрипт требует привилегий для прослушивания порта 67 и отправки сырых пакетов (raw sockets).
   - Linux: Запускайте через sudo -> sudo python3 dhcp_server.py
   - Windows: Запускайте командную строку (cmd) или PowerShell от имени Администратора,
     затем -> python dhcp_server.py
"""

import sys
import time
import logging
import ipaddress
import threading
import os

# 1. Проверка наличия scapy
try:
    from scapy.all import sniff, sendp, conf, get_if_hwaddr
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dhcp import BOOTP, DHCP
except ImportError:
    print("Ошибка: Библиотека 'scapy' не установлена.")
    print("Выполните: pip install scapy")
    print("Для Windows не забудьте установить Npcap (https://npcap.com/).")
    sys.exit(1)

# ==========================================
# КОНФИГУРАЦИЯ СЕРВЕРА
# ==========================================
if os.name == 'nt':
    #Настройки для Windows
    INTERFACE = "Intel(R) PRO/1000 MT Desktop Adapter"
else:

    INTERFACE = "enp0s3"  # Имя интерфейса (замените на свое, см. инструкцию)
SERVER_IP = "192.168.56.1"  # Статический IP-адрес этого сервера
POOL_START = "192.168.56.100"  # Начало пула адресов
POOL_END = "192.168.56.150"  # Конец пула адресов
SUBNET_MASK = "255.255.255.0"  # Маска подсети
GATEWAY = "192.168.56.1"  # Шлюз по умолчанию (можно оставить IP сервера)
DNS_SERVER = "8.8.8.8"  # DNS сервер
LEASE_TIME = 3600  # Время аренды в секундах (1 час)
# ==========================================

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class DHCPServer:
    def __init__(self):
        self.interface = INTERFACE
        self.server_ip = SERVER_IP

        try:# Пытаемся получить MAC-адрес интерфейса для отправки ответов
            self.server_mac = get_if_hwaddr(self.interface)
        except Exception as e:
            logging.error(f"Не удалось получить MAC-адрес интерфейса {self.interface}: {e}")
            logging.error("Проверьте правильность имени интерфейса.")
            sys.exit(1)

        # Генерация пула доступных IP-адресов
        try:
            start_ip = int(ipaddress.IPv4Address(POOL_START))
            end_ip = int(ipaddress.IPv4Address(POOL_END))
            self.ip_pool = [str(ipaddress.IPv4Address(ip)) for ip in range(start_ip, end_ip + 1)]
        except Exception as e:
            logging.error(f"Ошибка конфигурации пула IP: {e}")
            sys.exit(1)

        # Таблица аренды: { "mac_address": {"ip": "192.168.x.x", "expires": timestamp} }
        self.leases = {}
        self.lock = threading.Lock()

    def get_dhcp_option(self, dhcp_options, key):
        """Извлекает значение конкретной опции из списка опций DHCP."""
        for option in dhcp_options:
            if isinstance(option, tuple) and option[0] == key:
                return option[1]
        return None

    def allocate_ip(self, mac_address, requested_ip=None):
        """Выделяет IP-адрес для клиента. Возвращает IP или None, если пул исчерпан."""
        with self.lock:
            now = time.time()

            # Очистка истекших аренд
            expired_macs = [m for m, data in self.leases.items() if data['expires'] < now]
            for m in expired_macs:
                released_ip = self.leases[m]['ip']
                del self.leases[m]
                if released_ip not in self.ip_pool:
                    self.ip_pool.append(released_ip)
                logging.info(f"Аренда истекла для MAC {m} (IP: {released_ip})")

            # Если клиент уже имеет аренду
            if mac_address in self.leases:
                self.leases[mac_address]['expires'] = now + LEASE_TIME
                return self.leases[mac_address]['ip']

            # Если клиент запрашивает конкретный IP, и он свободен
            if requested_ip and requested_ip in self.ip_pool:
                self.ip_pool.remove(requested_ip)
                self.leases[mac_address] = {'ip': requested_ip, 'expires': now + LEASE_TIME}
                return requested_ip

            # Выделение нового IP из пула
            if self.ip_pool:
                ip = self.ip_pool.pop(0)
                self.leases[mac_address] = {'ip': ip, 'expires': now + LEASE_TIME}
                return ip

            return None # Пул исчерпан

    def build_dhcp_reply(self, packet, msg_type, client_ip):
        """Создает ответный DHCP-пакет."""
        client_mac = packet[Ether].src
        xid = packet[BOOTP].xid

        # Формируем Ethernet и IP слои (отвечаем всегда широковещательно для надежности на этапе настройки)
        eth = Ether(src=self.server_mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src=self.server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)

        # Формируем BOOTP
        # op=2 означает BOOTREPLY
        bootp = BOOTP(
            op=2,
            yiaddr=client_ip,
            siaddr=self.server_ip,
            chaddr=packet[BOOTP].chaddr,
            xid=xid
        )

        # Опции DHCP
        dhcp_opts = [
            ("message-type", msg_type),
            ("subnet_mask", SUBNET_MASK),
            ("router", GATEWAY),
            ("name_server", DNS_SERVER),
            ("lease_time", LEASE_TIME),
            ("server_id", self.server_ip),
            "end"
        ]
        dhcp = DHCP(options=dhcp_opts)

        return eth / ip / udp / bootp / dhcp

    def handle_packet(self, packet):
        """Обрабатывает входящие DHCP пакеты."""
        if not packet.haslayer(DHCP):
            return
        mac_address = packet[Ether].src
        dhcp_options = packet[DHCP].options
        msg_type = self.get_dhcp_option(dhcp_options, "message-type")
        requested_ip = self.get_dhcp_option(dhcp_options, "requested_addr")

        # 1. Обработка DHCPDISCOVER
        if msg_type == 1:
            logging.info(f"Получен DHCPDISCOVER от {mac_address}")
            ip = self.allocate_ip(mac_address, requested_ip)
            if ip:
                reply = self.build_dhcp_reply(packet, msg_type=2, client_ip=ip) # DHCPOFFER = 2
                sendp(reply, iface=self.interface, verbose=0)
                logging.info(f"Отправлен DHCPOFFER: IP {ip} для {mac_address}")
            else:
                logging.warning(f"Пул адресов исчерпан! Невозможно предложить IP для {mac_address}")

        # 2. Обработка DHCPREQUEST
        elif msg_type == 3:
            logging.info(f"Получен DHCPREQUEST от {mac_address} на IP {requested_ip}")
            # Проверяем, наш ли это сервер (в мультисерверных сетях)
            server_id = self.get_dhcp_option(dhcp_options, "server_id")
            if server_id and server_id != self.server_ip:
                return # Запрос адресован другому серверу

            ip = self.allocate_ip(mac_address, requested_ip)

            # Если выделенный IP совпадает с запрошенным (или клиент продлевает текущий)
            if ip and (requested_ip == ip or requested_ip is None):
                reply = self.build_dhcp_reply(packet, msg_type=5, client_ip=ip) # DHCPACK = 5
                sendp(reply, iface=self.interface, verbose=0)
                logging.info(f"Отправлен DHCPACK: Подтвержден IP {ip} для {mac_address}")
            else:
                # Если IP уже занят или конфликт
                reply = self.build_dhcp_reply(packet, msg_type=6, client_ip="0.0.0.0") # DHCPNAK = 6
                sendp(reply, iface=self.interface, verbose=0)
                logging.warning(f"Отправлен DHCPNAK: Отказано в IP {requested_ip} для {mac_address}")

        # 3. Обработка DHCPRELEASE
        elif msg_type == 7:
            client_ip = packet[IP].src
            logging.info(f"Получен DHCPRELEASE от {mac_address} для IP {client_ip}")
            with self.lock:
                if mac_address in self.leases and self.leases[mac_address]['ip'] == client_ip:
                    self.ip_pool.append(client_ip)
                    del self.leases[mac_address]
                    logging.info(f"Аренда IP {client_ip} досрочно завершена клиентом {mac_address}")

    def start(self):
        """Запускает сниффер пакетов на порту 67."""
        logging.info(f"Запуск DHCP-сервера на интерфейсе {self.interface} (IP: {self.server_ip})")
        logging.info(f"Пул адресов: {POOL_START} - {POOL_END}")
        logging.info("Ожидание DHCP-запросов... (Нажмите Ctrl+C для остановки)")

        try:
            # Слушаем UDP порт 67 (DHCP Server). store=0 предотвращает утечку памяти.
            sniff(
                filter="udp and port 67",
                prn=self.handle_packet,
                iface=self.interface,
                store=0
            )
        except KeyboardInterrupt:
            logging.info("DHCP-сервер остановлен.")
        except Exception as e:
            logging.error(f"Ошибка при прослушивании сети: {e}")
            logging.error("Убедитесь, что скрипт запущен с правами администратора (sudo на Linux, Admin на Windows).")



if __name__ == "__main__":
  #  Установка интерфейса Scapy перед запуском

    conf.iface = INTERFACE
    conf.verb = 0 # Отключаем лишний вывод Scapy

server = DHCPServer()
server.start()
