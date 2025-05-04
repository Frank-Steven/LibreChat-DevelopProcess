# 第一阶段：构建依赖
FROM python:3.9-alpine AS builder

# 安装编译依赖
RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev \
    tk-dev \
    tcl-dev

WORKDIR /install
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# 第二阶段：运行时镜像
FROM python:3.9-alpine

# 从builder阶段复制已安装的包
COPY --from=builder /root/.local /root/.local
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

# 安装运行时依赖
RUN apk add --no-cache \
    tk \
    tcl \
    wqy-zenhei \
    font-noto \
    busybox-extras \
    && ln -s /root/.local/bin/* /usr/local/bin/

# 设置中文环境变量
ENV LANG zh_CN.UTF-8
ENV LANGUAGE zh_CN:zh
ENV LC_ALL zh_CN.UTF-8

WORKDIR /app
COPY . .

# 设置环境变量
ENV PATH=/root/.local/bin:$PATH
ENV DISPLAY=host.docker.internal:0

CMD ["python", "chat_app.py"]
    