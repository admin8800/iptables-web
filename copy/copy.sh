#!/bin/bash

HOST=""
PASSWORD=""
SERVICE_FILE="/etc/systemd/system/iptables-copy.service"

# 解析传入的参数
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -host) HOST="$2"; shift ;;       # 获取主机地址
        -password) PASSWORD="$2"; shift ;; # 获取密码
    esac
    shift
done

# 检查是否提供了必需的主机和密码参数
if [[ -z "$HOST" || -z "$PASSWORD" ]]; then
    echo "错误：必须提供 -host 和 -password 参数"
    exit 1
fi

if [ -f /usr/local/bin/iptables-copy ]; then
    echo "/usr/local/bin/iptables-copy 已存在，正在删除旧文件..."
    rm -f /usr/local/bin/iptables-copy
fi


wget -qO /usr/local/bin/iptables-copy https://github.com/admin8800/iptables-web/raw/main/copy/iptables-copy
chmod +x /usr/local/bin/iptables-copy

if [ -f "$SERVICE_FILE" ]; then
    echo "$SERVICE_FILE 文件已存在，正在覆盖..."
    rm -f "$SERVICE_FILE"
fi

# 创建或覆盖 systemd 服务文件
echo "创建或覆盖 systemd 服务文件..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Iptables Copy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/iptables-copy -host "$HOST" -password "$PASSWORD"
Restart=always
User=root
Environment=HOST=$HOST
Environment=PASSWORD=$PASSWORD

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iptables-copy.service
systemctl start iptables-copy.service

echo "iptables-copy 服务已安装并启用。"
