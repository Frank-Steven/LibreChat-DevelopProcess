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
        self.last_message_time = {}  # 初始化最后消息时间字典

    def setup_master_window(self):
        self.master.title("P2P Chat v1.0")
        self.master.geometry("800x600")
        # 设置最小窗口尺寸，防止UI元素溢出
        self.master.minsize(700, 500)
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
        self.last_active_time = {}  # 记录每个peer的最后活跃时间
        self.peer_timeout = 15  # 15秒无响应视为离线

    def create_widgets(self):
        # 使用grid布局管理器
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        
        # 主框架使用grid布局
        main_frame = ttk.Frame(self.master, padding="5")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 用户列表框架
        self.user_frame = ttk.Frame(main_frame, width=200)
        self.user_listbox = tk.Listbox(self.user_frame, bg="#f0f0f0", bd=2,
                                     relief=tk.SUNKEN, highlightthickness=0, 
                                     font=("Arial", 12))
        self.user_scrollbar = ttk.Scrollbar(self.user_frame, orient="vertical", 
                                         command=self.user_listbox.yview)
        self.user_listbox.configure(yscrollcommand=self.user_scrollbar.set)
        self.user_listbox.bind('<<ListboxSelect>>', self.select_user)
        
        # 用户列表布局
        self.user_listbox.grid(row=0, column=0, sticky="nsew")
        self.user_scrollbar.grid(row=0, column=1, sticky="ns")
        self.user_frame.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        self.user_frame.grid_rowconfigure(0, weight=1)
        self.user_frame.grid_columnconfigure(0, weight=1)
        
        # 聊天框架
        self.chat_frame = ttk.Frame(main_frame)
        self.chat_frame.grid(row=0, column=1, sticky="nsew")
        self.chat_frame.grid_rowconfigure(1, weight=1)
        self.chat_frame.grid_columnconfigure(0, weight=1)
        
        # 聊天顶部区域
        self.create_chat_top_frame()
        self.create_chat_title()
        self.create_chat_window()
        self.create_input_frame()

    def create_chat_top_frame(self):
        top_frame = ttk.Frame(self.chat_frame, height=40)  # 设置固定高度
        top_frame.grid(row=0, column=0, sticky="ew", pady=(0,5))
        top_frame.grid_propagate(False)  # 禁止自动调整大小
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_rowconfigure(0, weight=0)  # 明确设置权重为0
        
        self.username_label = ttk.Label(top_frame, 
                                      text=f"当前用户: {self.username}", 
                                      anchor="w", 
                                      font=("Arial", 12))
        self.username_label.grid(row=0, column=0, sticky="w", padx=5)
        
        change_username_button = ttk.Button(top_frame, 
                                          text="修改用户名", 
                                          command=self.change_username)
        change_username_button.grid(row=0, column=1, sticky="e", padx=5)

    def create_chat_title(self):
        self.chat_title = ttk.Label(self.chat_frame, 
                                 text="LibreChat", 
                                 anchor="w", 
                                 font=("Arial", 14))
        self.chat_title.grid(row=1, column=0, sticky="ew", padx=5, pady=(0,5))
        self.chat_frame.rowconfigure(1, weight=0)  # 标题行权重设为0

    def create_chat_window(self):
        self.chat_window = scrolledtext.ScrolledText(self.chat_frame, 
                                                  bg="#ffffff", 
                                                  bd=0,
                                                  highlightthickness=0, 
                                                  state=tk.DISABLED,
                                                  wrap=tk.WORD)
        self.chat_window.tag_config("blue", foreground="blue", font=("Arial", 12))
        self.chat_window.tag_config("green", foreground="green", font=("Arial", 12))
        self.chat_window.tag_config("timestamp", foreground="gray", font=("Arial", 10))
        self.chat_window.grid(row=2, column=0, sticky="nsew", padx=5, pady=(0,5))
        # 明确设置消息窗口权重为1，其他区域权重为0
        self.chat_frame.rowconfigure(0, weight=0)  # 顶部状态栏
        self.chat_frame.rowconfigure(1, weight=0)  # 标题
        self.chat_frame.rowconfigure(2, weight=1)  # 消息窗口
        self.chat_frame.rowconfigure(3, weight=0)  # 输入框

    def create_input_frame(self):
        self.input_frame = ttk.Frame(self.chat_frame)
        self.input_frame.grid(row=3, column=0, sticky="ew", pady=(0,5))
        self.input_frame.grid_columnconfigure(0, weight=1)
        
        # 增加输入框高度
        self.input_entry = ttk.Entry(self.input_frame, state=tk.DISABLED)
        self.input_entry.grid(row=0, column=0, sticky="ew", padx=(0,5), ipady=10)  # 增加ipady参数
        self.input_entry.bind("<Return>", self.send_message)
        
        send_button = ttk.Button(self.input_frame, 
                               text="发送", 
                               width=8, 
                               command=lambda: self.send_message(None), 
                               state=tk.DISABLED)
        send_button.grid(row=0, column=1, sticky="e")
        
        # 设置输入框框架固定高度
        self.input_frame.config(height=50)
        self.input_frame.grid_propagate(False)

    def get_local_ip(self):
        """获取本机真实局域网IP"""
        try:
            # 方法1：通过UDP连接获取外网IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip != '127.0.0.1':
                    return ip
                
            # 方法2：获取所有接口IP
            hostname = socket.gethostname()
            ips = socket.gethostbyname_ex(hostname)[2]
            for ip in ips:
                if ip != '127.0.0.1' and not ip.startswith('169.254.'):
                    return ip
            raise Exception("No valid IP address found")
        except Exception as e:
            messagebox.showerror("错误", f"无法获取本机IP地址: {e}")
            raise

    def setup_networking(self):
        self.start_broadcast_listener()
        self.start_chat_server()
        self.start_broadcast_timer()
        # 启动peer状态检查定时器
        self.master.after(5000, self.check_peer_status)

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

    def get_network_broadcast_address(self, ip_address):
        """根据IP地址计算广播地址"""
        try:
            if ip_address == '127.0.0.1':
                return '127.255.255.255'
                
            # 获取网络接口信息
            interfaces = socket.if_nameindex()
            for interface in interfaces:
                ifname = interface[1]
                addr_info = socket.getaddrinfo(ifname, 0)
                for addr in addr_info:
                    if addr[4][0] == ip_address:
                        # 简单处理：假设子网掩码是255.255.0.0
                        network_part = '.'.join(ip_address.split('.')[:2])
                        return f"{network_part}.255.255"
            return '255.255.255.255'
        except:
            return '255.255.255.255'

    def broadcast_presence(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = self.get_broadcast_message()
            local_ip = self.get_local_ip()
            broadcast_address = self.get_network_broadcast_address(local_ip)
            print(f"[DEBUG] Using broadcast address: {broadcast_address}")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(message.encode(), (broadcast_address, self.broadcast_port))
            print(f"[DEBUG] Broadcast sent to {broadcast_address}:{self.broadcast_port}")
            self.broadcast_timer = threading.Timer(self.broadcast_interval, self.broadcast_presence)
            self.broadcast_timer.start()
        except Exception as e:
            print(f"Broadcast error: {e}")
            # 尝试使用有限广播地址作为后备
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(message.encode(), ('255.255.255.255', self.broadcast_port))
                print(f"[DEBUG] Fallback to limited broadcast")
            except Exception as fallback_e:
                print(f"Fallback broadcast also failed: {fallback_e}")

    def get_broadcast_message(self):
        return json.dumps({
            'username': self.username,
            'ip': self.get_local_ip(),  # 使用新的IP获取方法
            'port': self.chat_port
        })

    def listen_for_broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 绑定到所有接口，使用广播端口
        sock.bind(('0.0.0.0', self.broadcast_port))
        # 允许接收广播消息
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        print(f"[DEBUG] Listening for broadcasts on port {self.broadcast_port}")
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                print(f"[DEBUG] Received broadcast from {addr}: {data.decode()}")
                peer_info = json.loads(data.decode())

                # 过滤自己的广播消息
                if peer_info['ip'] == self.get_local_ip():
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
        ip = peer_info['ip']
        self.peers[ip] = peer_info
        self.last_active_time[ip] = datetime.now()  # 更新最后活跃时间
        if ip not in self.message_records:
            self.message_records[ip] = []
            self.unread_counts[ip] = 0
            self.last_message_time[ip] = datetime.min  # 初始化最早时间

    def start_chat_server_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.get_local_ip(), self.chat_port))
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
                # 更新最后消息时间
                self.last_message_time[peer_ip] = datetime.now()
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
            'from_ip': self.get_local_ip(),  # 使用新的IP获取方法
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
        """更新用户列表显示
        1. 清空当前列表
        2. 检查是否有在线用户
        3. 按最后消息时间排序用户
        4. 为每个用户生成显示文本并添加到列表
        5. 根据在线状态设置显示颜色
        """
        self.user_listbox.delete(0, tk.END)
        
        if not self.peers:
            return
            
        # 按最后消息时间降序排序
        self.sorted_peers = sorted(
            self.peers.items(),
            key=lambda x: self.last_message_time.get(x[0], datetime.min),
            reverse=True
        )
        
        # 添加每个用户到列表
        for peer_ip, peer in self.sorted_peers:
            display_text = self._generate_user_display_text(peer_ip, peer)
            self.user_listbox.insert(tk.END, display_text)
            
            # 设置用户颜色：在线-黑色，离线-灰色
            is_online = self._check_user_online_status(peer_ip)
            self.user_listbox.itemconfig(
                tk.END,
                {'fg': 'black' if is_online else 'gray'}
            )

    def _generate_user_display_text(self, peer_ip, peer):
        """生成用户列表显示文本
        参数:
            peer_ip: 用户IP地址
            peer: 用户信息字典
        返回:
            格式化后的显示文本
        """
        unread = self.unread_counts[peer_ip]
        last_msg = self.message_records[peer_ip][-1] if self.message_records[peer_ip] else None
        
        # 检查用户在线状态
        is_online = self._check_user_online_status(peer_ip)
        
        # 格式化最后一条消息
        if last_msg:
            sender = last_msg['from']
            msg = last_msg['message']
            msg_short = msg[:10] + "..." if len(msg) > 10 else msg
            last_msg_display = f"{sender}: {msg_short}"
        else:
            last_msg_display = ""
            
        # 组合显示文本
        unread_display = f"({unread}条) " if unread > 0 else ""
        status = "" if is_online else " [离线]"
        return f"{unread_display}{peer['username']}{status} [{last_msg_display}]"

    def _check_user_online_status(self, peer_ip):
        """检查用户在线状态
        参数:
            peer_ip: 用户IP地址
        返回:
            bool: True表示在线，False表示离线
        """
        return (datetime.now() - self.last_active_time.get(peer_ip, datetime.now())).total_seconds() <= self.peer_timeout

    def _update_ui_controls_status(self, is_online):
        """更新UI控件状态
        参数:
            is_online: 用户是否在线
        """
        # 更新输入框状态
        self.input_entry.config(state=tk.NORMAL if is_online else tk.DISABLED)
        
        # 更新发送按钮状态
        send_button = self.input_frame.winfo_children()[1]
        send_button.config(state=tk.NORMAL if is_online else tk.DISABLED)
        
        # 更新聊天标题状态
        status_text = " (离线)" if not is_online else ""
        self.chat_title.config(text=f"{self.selected_peer['username']}{status_text}")

    def _display_chat_history(self, peer_ip):
        """显示聊天历史记录
        参数:
            peer_ip: 用户IP地址
        """
        self.input_entry.focus()
        self.chat_window.config(state=tk.NORMAL)
        self.chat_window.delete(1.0, tk.END)
        for msg in self.message_records[peer_ip]:
            self.display_message(msg)
        self.chat_window.config(state=tk.DISABLED)

    def check_peer_status(self):
        """检查peer是否离线"""
        current_time = datetime.now()
        for peer_ip, last_time in self.last_active_time.items():
            if (current_time - last_time).total_seconds() > self.peer_timeout:
                # 对方离线，更新UI状态
                if self.selected_peer and self.selected_peer['ip'] == peer_ip:
                    self.master.after(0, self.update_ui_status, False)
        # 每隔5秒检查一次
        self.master.after(5000, self.check_peer_status)

    def _update_ui_controls_status(self, is_online):
        """更新UI控件状态
        参数:
            is_online: 用户是否在线
        """
        # 更新输入框状态
        self.input_entry.config(state=tk.NORMAL if is_online else tk.DISABLED)
        
        # 更新发送按钮状态
        send_button = self.input_frame.winfo_children()[1]
        send_button.config(state=tk.NORMAL if is_online else tk.DISABLED)
        
        # 更新聊天标题状态
        status_text = " (离线)" if not is_online else ""
        self.chat_title.config(text=f"{self.selected_peer['username']}{status_text}")

    def select_user(self, event):
        """处理用户选择事件
        1. 获取选中的用户
        2. 更新UI状态
        3. 显示对应聊天记录
        4. 重置未读消息计数
        """
        selected = self.user_listbox.curselection()
        if selected:
            # 从排序后的列表中获取选中用户
            peer_ip, peer = self.sorted_peers[selected[0]]
            self.selected_peer = peer
            
            # 更新UI状态
            is_online = self._check_user_online_status(peer_ip)
            self._update_ui_controls_status(is_online)
            
            # 显示聊天记录
            self._display_chat_history(peer_ip)
            
            # 重置未读计数并更新列表
            self.unread_counts[peer_ip] = 0
            self.update_user_list()
        else:
            # 未选择用户时禁用输入控件
            self.input_entry.config(state=tk.DISABLED)
            self.input_frame.winfo_children()[1].config(state=tk.DISABLED)

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
    
