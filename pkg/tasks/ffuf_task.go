package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/models"

	"github.com/hibiken/asynq"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type FfufTask struct {
	TaskTemplate
	resultDAO *dao.ResultDAO
	targetDAO *dao.TargetDAO
	configDAO *dao.ConfigDAO // 新增配置DAO
}

func NewFfufTask(taskDAO *dao.TaskDAO, targetDAO *dao.TargetDAO, resultDAO *dao.ResultDAO, configDAO *dao.ConfigDAO) *FfufTask {
	return &FfufTask{
		TaskTemplate: TaskTemplate{TaskDAO: taskDAO},
		resultDAO:    resultDAO,
		targetDAO:    targetDAO,
		configDAO:    configDAO, // 初始化配置DAO
	}
}

func (f *FfufTask) Handle(ctx context.Context, t *asynq.Task) error {
	return f.Execute(ctx, t, f.runFfuf)
}

func (f *FfufTask) runFfuf(ctx context.Context, t *asynq.Task) error {
	var payload struct {
		Target   string `json:"target"`
		TaskID   string `json:"task_id"`
		TargetID string `json:"target_id,omitempty"` // 改为 target_id
	}

	// 解析任务载荷
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("解析任务载荷失败: %v", err)
	}

	if payload.Target == "" {
		return fmt.Errorf("无效的目标 URL")
	}

	logging.Info("开始执行 ffuf 任务: %s", payload.Target)

	// 监听取消信号
	done := make(chan error, 1)
	var cmd *exec.Cmd
	var tempFile *os.File

	// 在协程中执行剩余的工作
	go func() {
		var err error

		// 从数据库获取默认工具配置
		toolConfig, err := f.configDAO.GetDefaultToolConfig()
		if err != nil {
			logging.Error("获取默认工具配置失败: %v", err)
			done <- fmt.Errorf("获取默认工具配置失败: %v", err)
			return
		}

		// 检查 Ffuf 是否启用
		if !toolConfig.FfufConfig.Enabled {
			logging.Warn("Ffuf 工具未启用，跳过任务执行")
			done <- nil
			return
		}

		// 创建临时文件
		tempFile, err = ioutil.TempFile("", "ffuf-result-*.json")
		if err != nil {
			done <- fmt.Errorf("创建临时文件失败: %v", err)
			return
		}

		// 准备 Ffuf 命令参数，使用配置中的设置
		ffufArgs := []string{
			"-u", payload.Target + "/FUZZ",
			"-w", toolConfig.FfufConfig.WordlistPath, // 使用配置中的字典路径
			"-o", tempFile.Name(),
			"-of", "json",
		}

		// 如果有指定 HTTP 状态码，添加参数
		if toolConfig.FfufConfig.MatchHttpCode != "" {
			ffufArgs = append(ffufArgs, "-mc", toolConfig.FfufConfig.MatchHttpCode)
		}

		// 如果有指定扩展名，添加参数
		if toolConfig.FfufConfig.Extensions != "" {
			ffufArgs = append(ffufArgs, "-e", toolConfig.FfufConfig.Extensions)
		}

		// 如果有指定线程数，添加参数
		if toolConfig.FfufConfig.Threads > 0 {
			ffufArgs = append(ffufArgs, "-t", fmt.Sprintf("%d", toolConfig.FfufConfig.Threads))
		}

		logging.Info("执行 ffuf 命令，参数: %v", ffufArgs)

		// 执行 ffuf 命令，使用上下文以支持取消
		cmd = exec.CommandContext(ctx, "ffuf", ffufArgs...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// 检查是否是因为取消而失败
			if ctx.Err() == context.Canceled {
				done <- ctx.Err() // 传递取消错误
				return
			}
			done <- fmt.Errorf("执行 ffuf 命令失败: %v, 输出: %s", err, string(output))
			return
		}

		// 读取临时文件内容
		result, err := ioutil.ReadFile(tempFile.Name())
		if err != nil {
			done <- fmt.Errorf("读取 ffuf 结果文件失败: %v", err)
			return
		}

		logging.Info("ffuf 任务完成，结果已保存到文件: %s", tempFile.Name())

		// 解析 ffuf 结果
		var ffufResult struct {
			Results []struct {
				Status int    `json:"status"`
				Length int    `json:"length"`
				Words  int    `json:"words"`
				Lines  int    `json:"lines"`
				URL    string `json:"url"`
			} `json:"results"`
		}
		if err := json.Unmarshal(result, &ffufResult); err != nil {
			done <- fmt.Errorf("解析 ffuf 结果失败: %v", err)
			return
		}

		// 处理 TargetID
		var targetID *primitive.ObjectID
		if payload.TargetID != "" {
			objID, err := primitive.ObjectIDFromHex(payload.TargetID)
			if err == nil {
				targetID = &objID
			}
		}

		// 创建 PathEntry 列表
		pathData := &models.PathData{
			Paths: make([]models.PathEntry, 0, len(ffufResult.Results)),
		}

		for _, r := range ffufResult.Results {
			entry := models.PathEntry{
				ID:         primitive.NewObjectID(),
				Path:       strings.TrimPrefix(r.URL, payload.Target),
				Status:     r.Status,
				Length:     r.Length,
				Words:      r.Words,
				Lines:      r.Lines,
				IsRead:     false,
				HTTPStatus: 0,
				HTTPTitle:  "",
			}
			if targetID != nil {
				entry.TargetID = targetID
			}
			pathData.Paths = append(pathData.Paths, entry)
		}

		// 创建扫描结果记录
		scanResult := &models.Result{
			ID:        primitive.NewObjectID(),
			Type:      "Path",
			Target:    payload.Target,
			Timestamp: time.Now(),
			Data:      pathData,
			TargetID:  targetID,
			IsRead:    false,
		}

		// 存储扫描结果
		if err := f.resultDAO.CreateResult(scanResult); err != nil {
			logging.Error("存储扫描结果失败: %v", err)
			done <- err
			return
		}

		logging.Info("成功处理并存储 ffuf 结果，共找到 %d 个路径", len(pathData.Paths))
		done <- nil
	}()

	// 等待任务完成或被取消
	select {
	case err := <-done:
		// 任务完成或出错
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
		return err
	case <-ctx.Done():
		// 上下文被取消
		logging.Info("Ffuf 任务被取消: %s", payload.Target)
		return ctx.Err()
	}
}
