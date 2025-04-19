# 使用官方Python镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖（包含中文字体、X11支持和网络工具）
RUN apt-get update && apt-get install -y \
    python3-tk \
    fonts-wqy-zenhei \
    fonts-noto-cjk \
    locales \
    xauth \
    netcat-traditional \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 配置中文locale环境
RUN sed -i '/zh_CN.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen zh_CN.UTF-8

# 先复制requirements文件以利用Docker缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用程序代码
COPY . .

# 设置X11转发环境变量（实际运行时可能需要覆盖）
ENV DISPLAY=host.docker.internal:0

# 运行应用程序
CMD ["python", "chat_app.py"]
    