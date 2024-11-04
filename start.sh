#!/bin/bash

# 确保系统支持 iptables 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 启动 Flask 应用
python /app/app.py