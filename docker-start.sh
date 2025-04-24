#!/bin/bash


# 生成随机字符串
generate_random() {
    openssl rand -base64 32
}
echo "写入配置到.env文件"
cat > .env << EOF
JWT_SECRET=$(generate_random)
SESSION_SECRET=$(generate_random)
SERVER_PORT=31337
MONGODB_IP=mongodb
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=yangmiee_password
REDIS_PASSWORD=yangmiee_redis_password
REDIS_IP=redis
REDIS_PORT=6379
EOF

# 检查Docker和Docker Compose是否安装
if ! command -v docker &> /dev/null; then
    echo "Docker 未安装。请先安装Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# 设置平台参数
if [[ $(uname -m) == "arm64" ]] || [[ $(uname -m) == "aarch64" ]]; then
    export TARGETPLATFORM=linux/arm64
    echo "检测到ARM64架构，设置TARGETPLATFORM=linux/arm64"
else
    export TARGETPLATFORM=linux/amd64
    echo "使用默认amd64架构，设置TARGETPLATFORM=linux/amd64"
fi

# 创建必要的目录
mkdir -p logs

# 停止并移除现有容器（如果有）
echo "停止并移除现有容器（如果有）..."
docker-compose down

# 启动数据库服务
echo "正在启动数据库服务..."
docker-compose up -d mongodb redis
echo "等待数据库服务就绪..."
sleep 15

# 确保MongoDB和Redis已经启动
echo "检查数据库服务状态..."
if ! docker ps | grep yangmiee-mongodb > /dev/null; then
    echo "MongoDB服务未能正常启动，正在尝试重启..."
    docker-compose restart mongodb
    sleep 10
fi

if ! docker ps | grep yangmiee-redis > /dev/null; then
    echo "Redis服务未能正常启动，正在尝试重启..."
    docker-compose restart redis
    sleep 10
fi

# 启动后端服务
echo "正在启动Yangmiee后端服务..."
docker-compose up -d backend

# 检查服务状态
echo "等待服务启动..."
sleep 5
docker-compose ps

# 检查后端服务是否成功启动
if ! docker ps | grep yangmiee-backend > /dev/null; then
    echo "后端服务未能正常启动，正在尝试手动启动..."
    docker-compose up -d backend
    sleep 5
fi

echo ""
echo "Yangmiee服务已启动!"
echo "请使用以下地址访问:"
echo "http://0.0.0.0:31337 或 http://<您的服务器IP>:31337"
echo ""
echo "查看日志: docker-compose logs -f"
echo "停止服务: docker-compose down"
echo ""
echo "如果无法访问，请检查服务状态: docker-compose ps"
echo "重启服务: docker-compose restart" 