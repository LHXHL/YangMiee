package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/models"
	"yangmiee/pkg/tasks"

	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TaskService struct {
	taskDAO       *dao.TaskDAO
	asynqClient   *asynq.Client
	redisAddr     string
	redisPassword string // 添加Redis密码
}

// NewTaskService 创建一个新的 TaskService 实例
func NewTaskService(taskDAO *dao.TaskDAO, asynqClient *asynq.Client, redisAddr string) *TaskService {
	// 获取Redis密码
	redisPassword := os.Getenv("REDIS_PASSWORD")

	return &TaskService{
		taskDAO:       taskDAO,
		asynqClient:   asynqClient,
		redisAddr:     redisAddr,
		redisPassword: redisPassword,
	}
}

func (s *TaskService) Close() {
	if s.asynqClient != nil {
		s.asynqClient.Close()
	}
}

// CreateTask 创建一个新的通用任务并保存到数据库
func (s *TaskService) CreateTask(taskType string, payload interface{}, targetID *primitive.ObjectID) error {
	logging.Info("正在创建任务: 类型 %s", taskType)

	var payloadBytes []byte
	var err error

	// 检查 payload 是否已经是字符串
	if payloadStr, ok := payload.(string); ok {
		payloadBytes = []byte(payloadStr)
	} else {
		// 如果不是字符串，则尝试 JSON 序列化
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			logging.Error("序列化任务载荷失败: %v", err)
			return err
		}
	}

	// 创建任务对象
	task := &models.Task{
		Type:     taskType,
		Payload:  string(payloadBytes),
		Status:   models.TaskStatusPending,
		TargetID: targetID,
	}

	// 将任务保存到数据库
	if err := s.taskDAO.CreateTask(task); err != nil {
		logging.Error("创建任务失败: %v", err)
		return err
	}

	logging.Info("成功创建任务: 类型 %s", taskType)
	return nil
}

type StartTaskResult struct {
	Success []string          `json:"success"`
	Failed  map[string]string `json:"failed"` // taskId -> error message
}

func (s *TaskService) StartTasks(taskIDs []string) (*StartTaskResult, error) {
	logging.Info("正在批量启动任务: %v", taskIDs)

	result := &StartTaskResult{
		Success: make([]string, 0),
		Failed:  make(map[string]string),
	}

	// 批量获取任务信息
	tasks, err := s.taskDAO.GetTasksByIDs(taskIDs)
	if err != nil {
		logging.Error("批量获取任务信息失败: %v", err)
		return nil, err
	}

	// 将找到的任务ID映射到任务对象
	taskMap := make(map[string]*models.Task)
	for _, task := range tasks {
		taskMap[task.ID.Hex()] = task
	}

	// 创建批量任务
	taskGroups := make(map[string][]*asynq.Task)

	for _, taskID := range taskIDs {
		task, exists := taskMap[taskID]
		if !exists {
			result.Failed[taskID] = "任务未找到"
			continue
		}

		// 检查任务状态，如果是已取消、失败或已完成，先重置为待处理状态
		if task.Status == models.TaskStatusCancelled ||
			task.Status == models.TaskStatusFailed ||
			task.Status == models.TaskStatusCompleted {
			logging.Info("重置任务状态从 %s 到 pending: %s", task.Status, taskID)
			if err := s.taskDAO.UpdateTaskStatus(taskID, models.TaskStatusPending, "任务重新启动"); err != nil {
				result.Failed[taskID] = fmt.Sprintf("重置任务状态失败: %v", err)
				continue
			}
		} else if task.Status == models.TaskStatusRunning {
			// 对于正在运行的任务，直接将其重置为待处理状态
			logging.Info("将运行中任务重置为待处理状态: %s", taskID)
			if err := s.taskDAO.UpdateTaskStatus(taskID, models.TaskStatusPending, "任务重新启动"); err != nil {
				result.Failed[taskID] = fmt.Sprintf("重置任务状态失败: %v", err)
				continue
			}
		}

		payloadMap := map[string]interface{}{
			"task_id": task.ID.Hex(),
			"target":  task.Payload,
		}

		if task.TargetID != nil {
			payloadMap["target_id"] = task.TargetID.Hex()
		}

		payload, err := json.Marshal(payloadMap)
		if err != nil {
			result.Failed[taskID] = "序列化任务载荷失败"
			continue
		}

		// 按任务类型分组
		asynqTask := asynq.NewTask(task.Type, payload)
		taskGroups[task.Type] = append(taskGroups[task.Type], asynqTask)
	}

	// 批量提交任务到队列
	for taskType, tasks := range taskGroups {
		// 使用事务批量提交同类型的任务
		err := s.enqueueBatch(context.Background(), tasks)
		if err != nil {
			logging.Error("批量提交任务类型 %s 失败: %v", taskType, err)
			// 查找失败的任务ID
			for _, task := range tasks {
				var payloadMap map[string]interface{}
				if err := json.Unmarshal(task.Payload(), &payloadMap); err != nil {
					continue
				}
				if taskID, ok := payloadMap["task_id"].(string); ok {
					result.Failed[taskID] = "加入队列失败"
				}
			}
			continue
		}

		// 记录成功的任务
		for _, task := range tasks {
			var payloadMap map[string]interface{}
			if err := json.Unmarshal(task.Payload(), &payloadMap); err != nil {
				continue
			}
			if taskID, ok := payloadMap["task_id"].(string); ok {
				result.Success = append(result.Success, taskID)
			}
		}
	}

	logging.Info("批量启动任务完成，成功: %d, 失败: %d",
		len(result.Success), len(result.Failed))

	return result, nil
}

// enqueueBatch 批量将任务加入队列
func (s *TaskService) enqueueBatch(ctx context.Context, tasks []*asynq.Task) error {
	// 不使用 Pipeline，直接批量提交任务
	for _, task := range tasks {
		// 添加 MaxRetry(0) 选项，确保任务失败时不会重试
		if _, err := s.asynqClient.EnqueueContext(ctx, task, asynq.MaxRetry(0)); err != nil {
			return err
		}
	}
	return nil
}

// GetTaskByID 根据ID获取任务
func (s *TaskService) GetTaskByID(id string) (*models.Task, error) {
	logging.Info("正在获取任务: ID %s", id)

	task, err := s.taskDAO.GetTaskByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			logging.Warn("任务不存在: ID %s", id)
			return nil, fmt.Errorf("task not found")
		}
		logging.Error("获取任务失败: ID %s, 错误: %v", id, err)
		return nil, err
	}

	logging.Info("成功获取任务: ID %s", id)
	return task, nil
}

// GetAllTasks 获取所有任务
func (s *TaskService) GetAllTasks() ([]models.Task, error) {
	logging.Info("正在获取所有任务")

	tasks, err := s.taskDAO.GetAllTasks()
	if err != nil {
		logging.Error("获取所有任务失败: %v", err)
		return nil, err
	}

	logging.Info("成功获取所有任务，共 %d 个", len(tasks))
	return tasks, nil
}

type DeleteTaskResult struct {
	Success []string          `json:"success"`
	Failed  map[string]string `json:"failed"` // taskId -> error message
}

// DeleteTasks 批量删除任务
func (s *TaskService) DeleteTasks(ids []string) (*DeleteTaskResult, error) {
	logging.Info("正在批量删除任务: %v", ids)

	result := &DeleteTaskResult{
		Success: make([]string, 0),
		Failed:  make(map[string]string),
	}

	// 1. 从数据库中批量删除任务
	dbResult, err := s.taskDAO.DeleteTasks(ids)
	if err != nil {
		logging.Error("批量删除任务失败: %v", err)
		return nil, err
	}

	// 2. 从Asynq队列中删除任务
	inspector := s.GetTaskCleaner()

	// 获取所有可用队列
	queues, err := inspector.Queues()
	if err != nil {
		logging.Error("获取队列列表失败: %v", err)
		// 继续处理，因为数据库删除可能已经成功
	} else {
		// 遍历所有队列
		for _, queue := range queues {
			// 检查各种状态的任务列表
			taskLists := []struct {
				name     string
				listFunc func(string, ...asynq.ListOption) ([]*asynq.TaskInfo, error)
			}{
				{"待处理", inspector.ListPendingTasks},
				{"进行中", inspector.ListActiveTasks},
				{"已调度", inspector.ListScheduledTasks},
				{"重试中", inspector.ListRetryTasks},
				{"已归档", inspector.ListArchivedTasks},
				{"已完成", inspector.ListCompletedTasks},
			}

			// 创建任务ID到状态的映射
			idMap := make(map[string]bool)
			for _, id := range ids {
				idMap[id] = true
			}

			// 遍历所有状态的任务
			for _, tl := range taskLists {
				tasks, err := tl.listFunc(queue)
				if err != nil {
					logging.Error("获取队列[%s]%s任务列表失败: %v", queue, tl.name, err)
					continue
				}

				// 遍历任务找到匹配的任务ID
				for _, t := range tasks {
					var payloadMap map[string]interface{}
					if err := json.Unmarshal(t.Payload, &payloadMap); err != nil {
						continue
					}

					if taskID, ok := payloadMap["task_id"].(string); ok && idMap[taskID] {
						err = inspector.DeleteTask(queue, t.ID)
						if err != nil {
							logging.Error("从队列[%s]删除%s任务失败: %v", queue, tl.name, err)
							continue
						}
						logging.Info("成功从队列[%s]删除%s任务: %s", queue, tl.name, taskID)
					}
				}
			}
		}
	}

	// 合并数据库删除结果
	result.Success = dbResult.DeletedIDs
	result.Failed = dbResult.FailedIDs

	logging.Info("批量删除任务完成，成功: %d, 失败: %d",
		len(result.Success), len(result.Failed))

	return result, nil
}

type StopTaskResult struct {
	Success []string          `json:"success"`
	Failed  map[string]string `json:"failed"` // taskId -> error message
}

// StopTasks 停止正在运行的任务
func (s *TaskService) StopTasks(ids []string) (*StopTaskResult, error) {
	logging.Info("正在停止任务: %v", ids)

	result := &StopTaskResult{
		Success: make([]string, 0),
		Failed:  make(map[string]string),
	}

	// 获取任务信息
	tasksInfo, err := s.taskDAO.GetTasksByIDs(ids)
	if err != nil {
		logging.Error("获取任务信息失败: %v", err)
		return nil, err
	}

	// 将任务ID映射到任务信息
	taskMap := make(map[string]*models.Task)
	for _, task := range tasksInfo {
		taskMap[task.ID.Hex()] = task
	}

	// 处理每个任务ID
	for _, id := range ids {
		task, exists := taskMap[id]
		if !exists {
			result.Failed[id] = "任务不存在"
			continue
		}

		// 检查任务状态
		if task.Status != models.TaskStatusRunning {
			result.Failed[id] = fmt.Sprintf("任务状态不是运行中，当前状态: %s", task.Status)
			continue
		}

		// 尝试取消任务
		success := tasks.CancelTask(id)
		if !success {
			// 任务可能已经在运行队列中，但还未开始执行
			// 尝试从队列中删除任务
			inspector := s.GetTaskCleaner()

			// 获取所有队列
			queues, err := inspector.Queues()
			if err != nil {
				result.Failed[id] = "获取任务队列失败"
				continue
			}

			taskFoundInQueue := false
			for _, queue := range queues {
				// 检查活动任务和等待任务
				for _, listFunc := range []func(string, ...asynq.ListOption) ([]*asynq.TaskInfo, error){
					inspector.ListActiveTasks,
					inspector.ListPendingTasks,
					inspector.ListScheduledTasks,
				} {
					tasks, err := listFunc(queue)
					if err != nil {
						continue
					}

					// 查找匹配的任务
					for _, t := range tasks {
						var payloadMap map[string]interface{}
						if err := json.Unmarshal(t.Payload, &payloadMap); err != nil {
							continue
						}

						if taskID, ok := payloadMap["task_id"].(string); ok && taskID == id {
							// 找到匹配的任务，尝试删除
							if err := inspector.DeleteTask(queue, t.ID); err == nil {
								taskFoundInQueue = true
								break
							}
						}
					}

					if taskFoundInQueue {
						break
					}
				}

				if taskFoundInQueue {
					break
				}
			}

			if !taskFoundInQueue {
				// 任务不在队列中，也没有注册取消函数
				result.Failed[id] = "找不到任务或任务已完成"
				continue
			}
		}

		// 更新任务状态为已取消
		if err := s.taskDAO.UpdateTaskStatus(id, models.TaskStatusCancelled, "任务被手动停止"); err != nil {
			result.Failed[id] = "更新任务状态失败"
			continue
		}

		result.Success = append(result.Success, id)
	}

	logging.Info("停止任务完成，成功: %d, 失败: %d",
		len(result.Success), len(result.Failed))

	return result, nil
}

// GetTaskCleaner 返回用于清理队列中的任务的任务清理器
func (s *TaskService) GetTaskCleaner() *asynq.Inspector {
	// 使用支持密码的Redis客户端选项
	redisOpt := asynq.RedisClientOpt{Addr: s.redisAddr}
	if s.redisPassword != "" {
		redisOpt.Password = s.redisPassword
	}

	inspector := asynq.NewInspector(redisOpt)
	return inspector
}
