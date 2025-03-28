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

# 检查 iptables-copy 服务是否存在
if systemctl status iptables-copy.service >/dev/null 2>&1; then
    echo "iptables-copy 服务存在，正在停止服务并禁用开机自启..."
    systemctl stop iptables-copy.service
    systemctl disable iptables-copy.service
    rm -f /etc/systemd/system/iptables-copy.service
    rm -f /usr/local/bin/iptables-copy
    systemctl daemon-reload
else
    echo "没有旧的 iptables-copy 服务。"
fi


wget -qO /usr/local/bin/iptables-copy https://github.com/admin8800/iptables-web/raw/main/copy/iptables-copy
chmod +x /usr/local/bin/iptables-copy

# 创建或覆盖 systemd 服务文件
echo "创建服务文件..."
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

# 检查服务是否成功启动
if systemctl is-active --quiet iptables-copy.service; then
  echo "iptables-copy 服务安装完成并成功启动。"
else
  echo "iptables-copy 服务启动失败。"
fi
