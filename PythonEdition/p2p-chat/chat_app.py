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
        self.setup_master_window()
        self.setup_user_config()
        self.create_widgets()
        self.setup_networking()

    def setup_master_window(self):
        self.master.title("P2P Chat v1.0")
        self.master.geometry("800x600")
        self.master.minsize(600, 400)
        self.master.configure(bg="#f0f0f0")

    def setup_user_config(self):
        self.username = "User_" + socket.gethostname()[-3:]
        self.broadcast_port = 5000
        self.chat_port = 5001
        self.broadcast_interval = 5
        self.peers = {}
        self.selected_peer = None
        self.message_records = {}
        self.unread_counts = {}

    def create_widgets(self):
        main_frame = self.create_main_frame()
        self.create_user_listbox(main_frame)
        self.create_chat_frame(main_frame)

    def create_main_frame(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        return main_frame

    def create_user_listbox(self, main_frame):
        self.user_frame = ttk.Frame(main_frame)
        self.user_listbox = tk.Listbox(self.user_frame, width=30, height=20, bg="#f0f0f0", bd=2,
                                       relief=tk.SUNKEN, highlightthickness=0, font=("Arial", 12))
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.user_listbox.bind('<<ListboxSelect>>', self.select_user)
        self.user_scrollbar = ttk.Scrollbar(self.user_frame, orient="vertical", command=self.user_listbox.yview)
        self.user_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_listbox.configure(yscrollcommand=self.user_scrollbar.set)
        self.user_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y, expand=False)

    def create_chat_frame(self, main_frame):
        self.chat_frame = ttk.Frame(main_frame)
        self.create_chat_top_frame()
        self.create_chat_title()
        self.create_chat_window()
        self.create_input_frame()
        self.chat_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    def create_chat_top_frame(self):
        top_frame = ttk.Frame(self.chat_frame)
        self.username_label = ttk.Label(top_frame, text=f"当前用户: {self.username}", anchor="w", font=("Arial", 16))
        self.username_label.pack(side=tk.LEFT, padx=10, pady=10)
        change_username_button = ttk.Button(top_frame, text="修改用户名", command=self.change_username)
        change_username_button.pack(side=tk.RIGHT, padx=10, pady=10)
        top_frame.pack(fill=tk.X)

    def create_chat_title(self):
        self.chat_title = ttk.Label(self.chat_frame, text="LibreChat", anchor="w", font=("Arial", 14))
        self.chat_title.pack(fill=tk.X, padx=5, pady=5)

    def create_chat_window(self):
        self.chat_window = scrolledtext.ScrolledText(self.chat_frame, bg="#ffffff", bd=0,
                                                     highlightthickness=0, state=tk.DISABLED)
        self.chat_window.tag_config("blue", foreground="blue", font=("Arial", 12))
        self.chat_window.tag_config("green", foreground="green", font=("Arial", 12))
        self.chat_window.tag_config("timestamp", foreground="gray", font=("Arial", 10))
        self.chat_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_input_frame(self):
        self.input_frame = ttk.Frame(self.chat_frame)
        self.input_entry = ttk.Entry(self.input_frame, width=50)
        self.input_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True, ipady=8)
        self.input_entry.bind("<Return>", self.send_message)
        send_button = ttk.Button(self.input_frame, text="发送", command=lambda: self.send_message(None))
        send_button.pack(side=tk.RIGHT, padx=5, pady=10)
        # 让输入框框架始终在底部，且宽度自适应
        self.input_frame.pack(fill=tk.X, side=tk.BOTTOM)

    def setup_networking(self):
        self.start_broadcast_listener()
        self.start_chat_server()
        self.start_broadcast_timer()

    def start_broadcast_listener(self):
        self.broadcast_listener = threading.Thread(target=self.listen_for_broadcast)
        self.broadcast_listener.daemon = True
        self.broadcast_listener.start()

    def start_chat_server(self):
        self.chat_listener = threading.Thread(target=self.start_chat_server_loop)
        self.chat_listener.daemon = True
        self.chat_listener.start()

    def start_broadcast_timer(self):
        self.broadcast_timer = threading.Timer(self.broadcast_interval, self.broadcast_presence)
        self.broadcast_timer.daemon = True
        self.broadcast_timer.start()

    def broadcast_presence(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = self.get_broadcast_message()
            broadcast_address = '172.19.255.255'
            # print(f"[DEBUG] Sending broadcast to {broadcast_address}:{self.broadcast_port}")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(message.encode(), (broadcast_address, self.broadcast_port))
            # print(f"[DEBUG] Broadcast sent successfully")
            self.broadcast_timer = threading.Timer(self.broadcast_interval, self.broadcast_presence)
            self.broadcast_timer.start()
        except Exception as e:
            print(f"Broadcast error: {e}")

    def get_broadcast_message(self):
        return json.dumps({
            'username': self.username,
            'ip': socket.gethostbyname(socket.gethostname()),
            'port': self.chat_port
        })

    def listen_for_broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.broadcast_port))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                print(f"[DEBUG] Received broadcast from {addr}: {data.decode()}")
                peer_info = json.loads(data.decode())

                # 过滤自己的广播消息
                if peer_info['ip'] == socket.gethostbyname(socket.gethostname()):
                    continue

                # 检查用户名冲突
                if peer_info['username'] == self.username:
                    # 生成一个新的用户名
                    new_username = "User_" + socket.gethostname()[-3:] + "_" + str(datetime.now().timestamp())[-3:]
                    # 强制修改用户名
                    self.master.after(0, self.force_change_username, new_username)
                    continue

                if peer_info['username'] != self.username:
                    self.update_peer_info(peer_info)
                    self.master.after(0, self.update_user_list)
            except Exception as e:
                print(f"Broadcast listener error: {e}")

    def force_change_username(self, new_username):
        """强制修改用户名"""
        self.username = new_username
        self.username_label.config(text=f"当前用户: {self.username}")
        self.broadcast_presence()
        messagebox.showinfo("用户名冲突", f"检测到用户名冲突，已自动修改为: {new_username}")

    def update_peer_info(self, peer_info):
        self.peers[peer_info['ip']] = peer_info
        if peer_info['ip'] not in self.message_records:
            self.message_records[peer_info['ip']] = []
            self.unread_counts[peer_info['ip']] = 0

    def start_chat_server_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', self.chat_port))
        sock.listen(5)
        while True:
            client_socket, addr = sock.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            # 接收消息长度头(4字节)
            length_header = client_socket.recv(4)
            if not length_header:
                return
                
            # 解析消息长度
            message_length = int.from_bytes(length_header, byteorder='big')
            
            # 接收完整消息
            chunks = []
            bytes_received = 0
            while bytes_received < message_length:
                chunk = client_socket.recv(min(message_length - bytes_received, 4096))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_received += len(chunk)
                
            data = b''.join(chunks).decode()
            message = json.loads(data)
            
            peer_ip = message.get('from_ip', None)
            if peer_ip in self.peers:
                self.message_records[peer_ip].append(message)
                if peer_ip != (self.selected_peer['ip'] if self.selected_peer else None):
                    self.unread_counts[peer_ip] += 1
                    self.master.after(0, self.update_user_list)
                else:
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
            message_data = self.get_outgoing_message(message)
            
            # 序列化消息
            message_json = json.dumps(message_data)
            
            # 发送消息长度头(4字节)
            sock.send(len(message_json).to_bytes(4, byteorder='big'))
            
            # 发送消息内容
            sock.sendall(message_json.encode())
            
            self.message_records[peer_ip].append(message_data)
            self.display_message(message_data)
            self.update_user_list()
        except Exception as e:
            messagebox.showerror("错误", f"发送失败: {e}")

    def get_outgoing_message(self, message):
        return {
            'from': self.username,
            'from_ip': socket.gethostbyname(socket.gethostname()),
            'message': message,
            'time': datetime.now().strftime("%H:%M:%S")
        }

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
            display_text = self.get_user_list_display_text(peer_ip, peer)
            self.user_listbox.insert(tk.END, display_text)
            self.user_listbox.itemconfig(tk.END, {'fg': 'gray'})

    def get_user_list_display_text(self, peer_ip, peer):
        unread = self.unread_counts[peer_ip]
        last_msg = self.message_records[peer_ip][-1] if self.message_records[peer_ip] else None
        if last_msg:
            sender = last_msg['from']
            msg = last_msg['message']
            msg_short = msg[:10] + "..." if len(msg) > 10 else msg
            last_msg_display = f"{sender}: {msg_short}"
        else:
            last_msg_display = ""
        unread_display = f"({unread}条) " if unread > 0 else ""
        return f"{unread_display}{peer['username']} [{last_msg_display}]"

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
        """修改后的用户名判重逻辑"""
        while True:
            new_username = simpledialog.askstring( 
                "修改用户名",
                "输入新用户名:",
                parent=self.master  
            )
            if not new_username:  # 用户取消输入 
                return 
                
            # 检查新名字是否与当前相同 
            if new_username == self.username: 
                messagebox.showinfo(" 提示", "新用户名与当前相同")
                return 
                
            # 检查长度限制 
            if len(new_username) > 20:
                messagebox.showerror(" 错误", "用户名不能超过20字符")
                continue 
                
            # 从peers字典中提取所有用户名进行比较 
            existing_usernames = [peer['username'] for peer in self.peers.values()] 
            if new_username in existing_usernames:
                messagebox.showerror(" 错误", f"用户名 {new_username} 已存在")
            else:
                self.username  = new_username 
                self.username_label.config(text=f" 当前用户: {self.username}") 
                self.broadcast_presence() 
                break 


if __name__ == "__main__":
    root = tk.Tk()
    app = P2PChatApp(root)
    root.mainloop()
    
