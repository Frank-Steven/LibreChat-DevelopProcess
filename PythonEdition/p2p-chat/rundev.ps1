#!/bin/bash

# 构建 Docker 镜像
docker build -t p2p-chat-app .

# rm -rf
docker rm -f p2p-chat-app-1 p2p-chat-app-2 p2p-chat-app-3

# 创建网络
docker network create --driver bridge p2p_network

# 运行 3 个容器
docker run -d --name p2p-chat-app-1 --network p2p_network -e DISPLAY=host.docker.internal:0 p2p-chat-app
docker run -d --name p2p-chat-app-2 --network p2p_network -e DISPLAY=host.docker.internal:0 p2p-chat-app
docker run -d --name p2p-chat-app-3 --network p2p_network -e DISPLAY=host.docker.internal:0 p2p-chat-app