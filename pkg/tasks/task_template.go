// task_template.go

package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/models"

	"github.com/hibiken/asynq"
)

// 存储正在执行的任务的取消函数
var (
	activeTasksMu  sync.RWMutex
	activeTasksCtx = make(map[string]context.CancelFunc)
	// 存储Redis地址，用于清理队列中的任务
	redisAddr     string
	redisPassword string
)

// InitTaskTemplate 初始化任务模板全局设置
func InitTaskTemplate(addr string) {
	redisAddr = addr
	// 从环境变量中获取Redis密码
	redisPassword = os.Getenv("REDIS_PASSWORD")
	if redisPassword != "" {
		logging.Info("任务模板初始化成功，Redis地址: %s，使用密码认证", redisAddr)
	} else {
		logging.Info("任务模板初始化成功，Redis地址: %s", redisAddr)
	}
}

// GetRedisClientOpt 获取Redis客户端选项
func GetRedisClientOpt() asynq.RedisClientOpt {
	opt := asynq.RedisClientOpt{Addr: redisAddr}
	if redisPassword != "" {
		opt.Password = redisPassword
	}
	return opt
}

// RegisterTaskCancellation 注册一个任务的取消函数
func RegisterTaskCancellation(taskID string, cancel context.CancelFunc) {
	activeTasksMu.Lock()
	defer activeTasksMu.Unlock()
	activeTasksCtx[taskID] = cancel
}

// UnregisterTaskCancellation 注销一个任务的取消函数
func UnregisterTaskCancellation(taskID string) {
	activeTasksMu.Lock()
	defer activeTasksMu.Unlock()
	delete(activeTasksCtx, taskID)
}

// CancelTask 取消一个运行中的任务
func CancelTask(taskID string) bool {
	activeTasksMu.RLock()
	cancel, exists := activeTasksCtx[taskID]
	activeTasksMu.RUnlock()

	if exists {
		cancel() // 调用取消函数
		return true
	}
	return false
}

// GetInspector 获取任务队列检查器，支持密码认证
func GetInspector() *asynq.Inspector {
	opt := asynq.RedisClientOpt{Addr: redisAddr}
	if redisPassword != "" {
		opt.Password = redisPassword
	}
	return asynq.NewInspector(opt)
}

// TaskTemplate 提供通用任务处理逻辑的模板
type TaskTemplate struct {
	TaskDAO *dao.TaskDAO
}

func (t *TaskTemplate) Execute(ctx context.Context, task *asynq.Task, handler func(context.Context, *asynq.Task) error) error {
	var payload map[string]string
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		logging.Error("解析任务载荷失败: %v", err)
		return err
	}

	taskID, ok := payload["task_id"]
	if !ok {
		logging.Error("任务载荷中缺少 task_id")
		return fmt.Errorf("缺少 task_id")
	}

	// 执行前检查任务的当前状态
	taskInfo, err := t.TaskDAO.GetTaskByID(taskID)
	if err != nil {
		logging.Error("获取任务信息失败: %s, 错误: %v", taskID, err)
		return err
	}

	// 如果任务已经是取消或失败状态，直接返回错误并不执行
	// 但不从队列中删除，这样可以之后重新启动
	if taskInfo.Status == models.TaskStatusCancelled {
		logging.Info("任务已被取消，不再执行: %s", taskID)
		return fmt.Errorf("任务已被取消: %s", taskID)
	}

	if taskInfo.Status == models.TaskStatusFailed {
		logging.Info("任务已标记为失败，不再执行: %s", taskID)
		return fmt.Errorf("任务已失败: %s", taskID)
	}

	if taskInfo.Status == models.TaskStatusCompleted {
		logging.Info("任务已完成，不再执行: %s", taskID)
		// 完成的任务也不从队列中删除，以便可以重启
		return fmt.Errorf("任务已完成: %s", taskID)
	}

	// 创建可取消的上下文
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 注册取消函数
	RegisterTaskCancellation(taskID, cancel)
	defer UnregisterTaskCancellation(taskID)

	// 更新任务状态为进行中
	if err := t.TaskDAO.UpdateTaskStatus(taskID, models.TaskStatusRunning, ""); err != nil {
		logging.Error("更新任务状态为进行中失败: %s, 错误: %v", taskID, err)
		return err
	}

	// 执行具体的任务处理逻辑
	err = handler(taskCtx, task)

	if err != nil {
		// 检查是否是被取消的上下文
		if taskCtx.Err() == context.Canceled {
			// 任务被手动取消
			if updateErr := t.TaskDAO.UpdateTaskStatus(taskID, models.TaskStatusCancelled, "任务被手动停止"); updateErr != nil {
				logging.Error("更新任务状态为已取消时出错: %s, 错误: %v", taskID, updateErr)
			}
			return fmt.Errorf("任务被取消: %s", taskID)
		}

		// 其他错误情况
		if updateErr := t.TaskDAO.UpdateTaskStatus(taskID, models.TaskStatusFailed, err.Error()); updateErr != nil {
			logging.Error("更新任务状态为失败时出错: %s, 错误: %v", taskID, updateErr)
		}
		return err
	}

	// 任务成功完成，更新状态为完成并记录结果
	if err := t.TaskDAO.UpdateTaskStatus(taskID, models.TaskStatusCompleted, "成功完成"); err != nil {
		logging.Error("更新任务状态为完成失败: %s, 错误: %v", taskID, err)
		return err
	}

	return nil
}
