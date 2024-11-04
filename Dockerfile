# 使用Python官方镜像作为基础镜像
FROM python:3.8.20-slim

# 安装必要的系统工具和iptables
RUN apt-get update && \
    apt-get install -y iptables net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制应用程序文件
COPY . /app/

# 安装Python依赖
RUN pip install flask

# 创建持久化目录
RUN mkdir -p /app/data

# 设置权限
RUN chmod +x /app/start.sh

# 暴露端口
EXPOSE 888

# 使用启动脚本
CMD ["/app/start.sh"]