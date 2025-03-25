#!/bin/bash

# 默认值
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

# 下载iptables-copy文件
echo "下载 iptables-copy 脚本..."
wget -qO /usr/local/bin/iptables-copy https://github.com/admin8800/iptables-web/raw/main/copy/iptables-copy
chmod +x /usr/local/bin/iptables-copy

# 创建 systemd 服务文件
echo "创建 systemd 服务文件..."
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

# 输出脚本配置
echo "iptables-copy 服务已安装并启用，服务将随着系统启动而自动运行。"
