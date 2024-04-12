import socket
from scapy.all import *
import tkinter as tk
from tkinter import filedialog

# Множество для отслеживания уникальных обращений
unique_requests = set()

# Получаем IP-адреса компьютера
def get_ip_addresses():
    ip_addresses = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
    return ip_addresses

# Обрабатываем сетевые пакеты
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        request = (src_ip, dst_ip)  # Создаем кортеж для представления обращения

        # Проверяем, было ли такое обращение уже обработано
        if request not in unique_requests:
            unique_requests.add(request) 
            output_text = f"{src_ip} --> {dst_ip}\n"
            text.insert(tk.END, output_text)
            save_button.config(state=tk.NORMAL)

# Сохраняем записи в файл
def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(text.get("1.0", tk.END))
        save_button.config(state=tk.DISABLED)

# Захватываем трафик
def sniff_traffic():
    sniff(prn=packet_callback, store=0)

# Создаем графический интерфейс
root = tk.Tk()
root.title("Сетевой монитор")

# Выводим IP-адреса компьютера
ip_label = tk.Label(root, text="IP-адреса компьютера:")
ip_label.pack()
ip_addresses = get_ip_addresses()
for ip in ip_addresses:
    ip_label = tk.Label(root, text=ip)
    ip_label.pack()

# Создаем текстовое поле для вывода обращений
text = tk.Text(root, height=20, width=50)
text.pack()

# Кнопка сохранения в файл
save_button = tk.Button(root, text="Сохранить в файл", command=save_to_file, state=tk.DISABLED)
save_button.pack()

# Запускаем захват сетевого трафика в отдельном потоке
sniff_thread = threading.Thread(target=sniff_traffic)
sniff_thread.start()

root.mainloop()