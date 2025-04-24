package setup

import (
	"context"
	"fmt"
	"os"
	"time"
	"yangmiee/pkg/logging"

	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ConnectToMongoDB 连接到MongoDB
func ConnectToMongoDB(defaultURI string) (*mongo.Client, error) {

	logging.Info("尝试连接到 MongoDB: %s", defaultURI)
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(defaultURI))
	if err != nil {
		logging.Error("连接 MongoDB 失败: %v", err)
		return nil, fmt.Errorf("连接 MongoDB 失败: %v", err)
	}
	logging.Info("成功连接到 MongoDB")
	return client, nil
}

// DisconnectMongoDB 断开MongoDB连接
func DisconnectMongoDB(client *mongo.Client) error {
	logging.Info("尝试断开 MongoDB 连接")
	if err := client.Disconnect(context.Background()); err != nil {
		logging.Error("MongoDB 断开连接失败: %v", err)
		return fmt.Errorf("MongoDB 断开连接失败: %v", err)
	}
	logging.Info("成功断开 MongoDB 连接")
	return nil
}

// InitAsynqClient 初始化Asynq客户端
func InitAsynqClient(defaultRedisAddr string) (*asynq.Client, error) {
	// 获取Redis密码
	redisPassword := os.Getenv("REDIS_PASSWORD")

	logging.Info("初始化 Asynq 客户端，Redis 地址: %s", defaultRedisAddr)

	clientOpt := asynq.RedisClientOpt{Addr: defaultRedisAddr}
	if redisPassword != "" {
		clientOpt.Password = redisPassword
		logging.Info("Redis 客户端使用密码认证")
	}

	client := asynq.NewClient(clientOpt)
	logging.Info("成功初始化 Asynq 客户端")
	return client, nil
}

// InitAsynqServer 初始化Asynq服务器
func InitAsynqServer(defaultRedisAddr string) (*asynq.Server, error) {

	// 获取Redis密码
	redisPassword := os.Getenv("REDIS_PASSWORD")

	logging.Info("初始化 Asynq 服务器，Redis 地址: %s", defaultRedisAddr)

	redisOpt := asynq.RedisClientOpt{Addr: defaultRedisAddr}
	if redisPassword != "" {
		redisOpt.Password = redisPassword
		logging.Info("Redis 服务器使用密码认证,密码为:%s", redisPassword)
	}

	server := asynq.NewServer(
		redisOpt,
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"default":  5,
				"critical": 10,
			},
			// 修改重试策略：任务失败后不自动重试，但保留在队列中
			RetryDelayFunc: func(n int, err error, task *asynq.Task) time.Duration {
				// 对于所有错误，返回非常长的延迟时间，实际上阻止了自动重试
				// 但任务仍然保留在队列中，可以手动重启
				return 24 * 365 * time.Hour // 一年的延迟，实际上就是不自动重试
			},
		},
	)
	logging.Info("成功初始化 Asynq 服务器，任务自动重试已禁用但可手动重启")
	return server, nil
}
