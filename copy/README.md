### 运行
```
bash <(curl -sL https://cdn.jsdelivr.net/gh/admin8800/iptables-web@main/copy/copy.sh) -host "主机地址" -password "密码"
```

查看状态
```
systemctl status iptables-copy.service
```
重启
```
systemctl restart iptables-copy.service
```
停止
```
systemctl stop iptables-copy.service
```
查看日志
```
journalctl -u iptables-copy.service -f
```
