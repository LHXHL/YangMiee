// handler.go

package tasks

import (
	"context"
	"fmt"
	"strings"
	"yangmiee/pkg/logging"

	"github.com/hibiken/asynq"
)

// TaskHandler 结构体用于实现 asynq.Handler 接口
type TaskHandler struct {
	handlers map[TaskType]TaskFunc
}

// TaskFunc 定义了处理任务的函数类型
type TaskFunc func(context.Context, *asynq.Task) error

// NewTaskHandler 创建一个新的 TaskHandler
func NewTaskHandler() *TaskHandler {
	return &TaskHandler{
		handlers: make(map[TaskType]TaskFunc),
	}
}

// RegisterHandler 注册特定类型任务的处理函数
func (h *TaskHandler) RegisterHandler(taskType TaskType, handler TaskFunc) {
	h.handlers[taskType] = handler
}

// ProcessTask 处理任务的方法
func (h *TaskHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	taskType := TaskType(task.Type())
	logging.Info("开始处理任务: %s", taskType)

	handler, exists := h.handlers[taskType]
	if !exists {
		err := fmt.Errorf("未知任务类型: %s", taskType)
		logging.Error("%v", err)
		return err
	}

	err := handler(ctx, task)
	if err != nil {
		logging.Error("处理任务失败 [%s]: %v", taskType, err)

		// 检查错误消息，如果包含特定标记，说明任务已被取消或已经处于结束状态
		if strings.Contains(err.Error(), "任务已被取消") ||
			strings.Contains(err.Error(), "任务被取消") ||
			strings.Contains(err.Error(), "任务已失败") ||
			strings.Contains(err.Error(), "任务已完成") {
			// 这些特殊状态不应该重试，直接返回错误
			return err
		}

		// 其他错误类型
		return err
	}

	logging.Info("任务处理完成: %s", taskType)
	return nil
}
