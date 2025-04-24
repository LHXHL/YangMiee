#!/bin/bash

generate_random() {
    openssl rand -base64 32
}

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