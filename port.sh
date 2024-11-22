#!/bin/bash

# 定义输出文件路径
OUTPUT_FILE="/home/rules.txt"

# 打开输出文件，写入头部注释
echo -e "机器端口\t\t目标IP和端口" > "$OUTPUT_FILE"

# 获取 iptables 转发规则并提取相关信息
sudo iptables -t nat -L PREROUTING -n -v | grep 'DNAT' | while read line; do
    # 提取本地端口和目标地址:端口
    LOCAL_PORT=$(echo "$line" | grep -oP 'dpt:\K[0-9]+')
    TARGET=$(echo "$line" | grep -oP 'to:[^ ]+')

    # 如果 LOCAL_PORT 和 TARGET 提取成功
    if [ -n "$LOCAL_PORT" ] && [ -n "$TARGET" ]; then
        # 格式化输出：本地端口 目标IP:端口
        TARGET_IP_PORT=$(echo "$TARGET" | sed 's/to://')
        echo -e "$LOCAL_PORT\t\t$TARGET_IP_PORT" >> "$OUTPUT_FILE"
    fi
done

# 去重操作，生成没有重复的规则文件
sort -u "$OUTPUT_FILE" -o "$OUTPUT_FILE"

# 输出生成的文件路径
echo "规则已保存到: $OUTPUT_FILE"
