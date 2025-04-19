import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from tkinter import ttk
import socket
import threading
import json
from datetime import datetime


class P2PChatApp:
    def __init__(self, master):
        self.master = master
        master.title("P2P Chat v1.0")
        master.geometry("800x600")
        master.minsize(600, 400)
        master.configure(bg="#f0f0f0")

        # 用户配置
        self.username = "User_" + socket.gethostname()[-3:]
        self.broadcast_port = 5000
        self.chat_port = 5001
        self.broadcast_interval = 5
        self.peers = {}
        self.selected_peer = None
        self.message_records = {}
        self.unread_counts = {}

        # 创建界面
        self.create_widgets()

        # 网络初始化
        self.setup_networking()

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 用户列表
        self.user_frame = ttk.Frame(main_frame)
        self.user_listbox = tk.Listbox(self.user_frame, width=20, height=30, bg="#ffffff", bd=0,
                                       highlightthickness=0)
        # 设置整个列表框的字体
        self.user_listbox.configure(font=("Arial", 10))
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.user_listbox.bind('<<ListboxSelect>>', self.select_user)

        # 聊天窗口
        self.chat_frame = ttk.Frame(main_frame)
        # 显示当前用户名和修改用户名按钮
        top_frame = ttk.Frame(self.chat_frame)
        self.username_label = ttk.Label(top_frame, text=f"当前用户名: {self.username}", anchor="w", font=("Arial", 14))
        self.username_label.pack(side=tk.LEFT, padx=5, pady=5)
        change_username_button = ttk.Button(top_frame, text="修改用户名", command=self.change_username)
        change_username_button.pack(side=tk.RIGHT, padx=5, pady=5)
        top_frame.pack(fill=tk.X)

        self.chat_title = ttk.Label(self.chat_frame, text="未选择聊天对象", anchor="w", font=("Arial", 14))
        self.chat_title.pack(fill=tk.X, padx=5, pady=5)
        self.chat_window = scrolledtext.ScrolledText(self.chat_frame, width=60, height=30, bg="#ffffff", bd=0,
                                                     highlightthickness=0, state=tk.DISABLED)
        # 配置聊天窗口的字体样式
        self.chat_window.tag_config("blue", foreground="blue", font=("Arial", 12))
        self.chat_window.tag_config("green", foreground="green", font=("Arial", 12))
        self.chat_window.tag_config("timestamp", foreground="gray", font=("Arial", 10))
        self.chat_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.input_frame = ttk.Frame(self.chat_frame)
        self.input_entry = ttk.Entry(self.input_frame, width=50)
        self.input_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True, ipady=8)
        self.input_entry.bind("<Return>", self.send_message)
        send_button = ttk.Button(self.input_frame, text="发送", command=lambda: self.send_message(None))
        send_button.pack(side=tk.RIGHT, padx=5, pady=10)
        self.input_frame.pack(fill=tk.X)

        # 布局
        self.user_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)
        self.chat_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    def setup_networking(self):
        # 启动广播监听
        self.broadcast_listener = threading.Thread(target=self.listen_for_broadcast)
        self.broadcast_listener.daemon = True
        self.broadcast_listener.start()

        # 启动聊天服务
        self.chat_listener = threading.Thread(target=self.start_chat_server)
        self.chat_listener.daemon = True
        self.chat_listener.start()

        # 定期广播自身存在
        self.broadcast_timer = threading.Timer(self.broadcast_interval, self.broadcast_presence)
        self.broadcast_timer.daemon = True
        self.broadcast_timer.start()

    def broadcast_presence(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = json.dumps({
                'username': self.username,
                'ip': socket.gethostbyname(socket.gethostname()),
                'port': self.chat_port
            })
            # 修改为正确的广播地址
            broadcast_address = '172.19.255.255' 
            print(f"[DEBUG] Sending broadcast to {broadcast_address}:{self.broadcast_port}")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(message.encode(), (broadcast_address, self.broadcast_port))
            print(f"[DEBUG] Broadcast sent successfully")
            self.broadcast_timer = threading.Timer(self.broadcast_interval, self.broadcast_presence)
            self.broadcast_timer.start()
        except Exception as e:
            print(f"Broadcast error: {e}")

    def listen_for_broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.broadcast_port))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                print(f"[DEBUG] Received broadcast from {addr}: {data.decode()}")
                peer_info = json.loads(data.decode())
                if peer_info['username'] != self.username:
                    self.peers[peer_info['ip']] = peer_info
                    if peer_info['ip'] not in self.message_records:
                        self.message_records[peer_info['ip']] = []
                        self.unread_counts[peer_info['ip']] = 0
                    self.master.after(0, self.update_user_list)
            except Exception as e:
                print(f"Broadcast listener error: {e}")

    def start_chat_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', self.chat_port))
        sock.listen(5)
        while True:
            client_socket, addr = sock.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            data = client_socket.recv(1024).decode()
            message = json.loads(data)
            peer_ip = message.get('from_ip', None)
            if peer_ip in self.peers:
                self.message_records[peer_ip].append(message)
                if peer_ip != (self.selected_peer['ip'] if self.selected_peer else None):
                    self.unread_counts[peer_ip] += 1
                    self.master.after(0, self.update_user_list)
                self.master.after(0, self.display_message, message)
        finally:
            client_socket.close()

    def send_message(self, event):
        message = self.input_entry.get()
        if not message:
            return
        self.input_entry.delete(0, tk.END)

        if not self.selected_peer:
            messagebox.showwarning("警告", "请先选择一个聊天对象")
            return

        peer_ip = self.selected_peer['ip']
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, self.chat_port))
            message_data = {
                'from': self.username,
                'from_ip': socket.gethostbyname(socket.gethostname()),
                'message': message,
                'time': datetime.now().strftime("%H:%M:%S")
            }
            sock.send(json.dumps(message_data).encode())
            self.message_records[peer_ip].append(message_data)
            self.display_message(message_data)
            self.update_user_list()
        except Exception as e:
            messagebox.showerror("错误", f"发送失败: {e}")

    def display_message(self, message):
        self.chat_window.config(state=tk.NORMAL)
        timestamp = message['time']
        sender = message['from']
        msg = message['message']
        formatted = f"[{timestamp}] {sender}:\n{msg}\n\n"
        color = "blue" if sender == self.username else "green"
        self.chat_window.insert(tk.END, formatted, (color,))
        self.chat_window.config(state=tk.DISABLED)
        self.chat_window.see(tk.END)

    def update_user_list(self):
        self.user_listbox.delete(0, tk.END)
        for peer_ip, peer in self.peers.items():
            unread = self.unread_counts[peer_ip]
            last_msg = self.message_records[peer_ip][-1] if self.message_records[peer_ip] else None
            if last_msg:
                sender = last_msg['from']
                msg = last_msg['message']
                msg_short = msg[:10] + "..." if len(msg) > 10 else msg
                last_msg_display = f"{sender}: {msg_short}"
            else:
                last_msg_display = ""
            unread_display = f"({unread}条未读) " if unread > 0 else ""
            # 消息预览换行并用浅色小字号
            display_text = f"{unread_display}{peer['username']}\n{last_msg_display}"
            self.user_listbox.insert(tk.END, display_text)
            self.user_listbox.itemconfig(tk.END, {'fg': 'gray'})

    def select_user(self, event):
        selected = self.user_listbox.curselection()
        if selected:
            peer_ip = list(self.peers.keys())[selected[0]]
            self.selected_peer = self.peers[peer_ip]
            self.input_entry.config(state=tk.NORMAL)
            self.input_entry.focus()
            self.chat_title.config(text=f"与 {self.selected_peer['username']} 聊天")
            self.chat_window.config(state=tk.NORMAL)
            self.chat_window.delete(1.0, tk.END)
            for msg in self.message_records[peer_ip]:
                self.display_message(msg)
            self.chat_window.config(state=tk.DISABLED)
            self.unread_counts[peer_ip] = 0
            self.update_user_list()

    def change_username(self):
        new_username = simpledialog.askstring("修改用户名", "请输入新的用户名：", initialvalue=self.username)
        if new_username:
            self.username = new_username
            self.username_label.config(text=f"当前用户名: {self.username}")
            self.broadcast_presence()


if __name__ == "__main__":
    root = tk.Tk()
    app = P2PChatApp(root)
    root.mainloop()
    