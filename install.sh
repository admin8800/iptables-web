#!/bin/bash

# 检查并安装 curl 和 wget
for pkg in curl wget; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        echo "$pkg 未安装，正在安装..."
        sudo apt update
        sudo apt install -y $pkg
    else
        echo "$pkg 已安装，跳过安装"
    fi
done

# 检查并安装 Docker
if ! command -v docker &> /dev/null; then
    echo "Docker 未安装，正在安装..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
else
    echo "Docker 已安装，跳过安装"
fi

# 检查容器是否已启动
if docker ps --format '{{.Names}}' | grep -q 'iptables-web'; then
    echo "iptables-web 容器已启动，跳过启动"
else
    echo "iptables-web 容器未启动，正在启动..."
    
    # 生成随机密码
    if [ -z "$AUTH_TOKEN" ]; then
        AUTH_TOKEN=$(openssl rand -base64 12)
        echo "生成的随机管理密码: $AUTH_TOKEN"
        echo "请妥善保存！"
    else
        echo "使用环境变量提供的管理密码"
    fi

    docker run -d \
        --name iptables-web \
        --privileged \
        --network host \
        --restart always \
        -e AUTH_TOKEN="$AUTH_TOKEN" \
        -v ./data:/app/data \
        ghcr.io/admin8800/iptables-web
fi
