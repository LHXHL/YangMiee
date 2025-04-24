package setup

import (
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/service"
	"yangmiee/pkg/tasks"

	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/mongo"
)

// InitTaskComponents 初始化任务相关组件
func InitTaskComponents(db *mongo.Database, defaultRedisAddr string) (*service.TaskService, *asynq.Server, error) {
	taskDAO := dao.NewTaskDAO(db.Collection("tasks"))

	asynqClient, err := InitAsynqClient(defaultRedisAddr)
	if err != nil {
		logging.Error("初始化 Asynq 客户端失败: %v", err)
		return nil, nil, err
	}
	logging.Info("Asynq 客户端初始化成功")

	taskService := service.NewTaskService(taskDAO, asynqClient, defaultRedisAddr)

	asynqServer, err := InitAsynqServer(defaultRedisAddr)
	if err != nil {
		asynqClient.Close()
		logging.Error("初始化 Asynq 服务器失败: %v", err)
		return nil, nil, err
	}
	logging.Info("Asynq 服务器初始化成功")

	return taskService, asynqServer, nil
}

// StartAsynqServer 启动 Asynq 服务器
func StartAsynqServer(server *asynq.Server, handler *tasks.TaskHandler, redisAddr string) {
	// 初始化任务模板，设置Redis地址
	tasks.InitTaskTemplate(redisAddr)
	logging.Info("任务模板已初始化")

	go func() {
		if err := server.Run(handler); err != nil {
			logging.Error("运行 Asynq 服务器失败: %v", err)
		}
	}()
	logging.Info("Asynq 服务器已启动")
}
