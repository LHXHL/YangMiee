package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/models"

	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type FscanResult struct {
	Ports     []PortInfo `json:"ports"`
	Vulns     []VulnInfo `json:"vulnerabilities"`
	WebInfo   []WebInfo  `json:"web_info"`
	ScanTime  float64    `json:"scan_time"`
	Target    string     `json:"target"`
	Timestamp time.Time  `json:"timestamp"`
}

// PortInfo 表示端口信息
type PortInfo struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
}

// VulnInfo 表示漏洞信息
type VulnInfo struct {
	Type        string `json:"type"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// WebInfo 表示Web信息
type WebInfo struct {
	URL    string `json:"url"`
	Code   int    `json:"code"`
	Length int    `json:"length"`
	Title  string `json:"title"`
}

// FscanTask 结构体定义了Fscan扫描任务
type FscanTask struct {
	TaskTemplate
	resultDAO *dao.ResultDAO
	targetDAO *dao.TargetDAO
	configDAO *dao.ConfigDAO
}

// NewFscanTask 创建一个新的Fscan任务
func NewFscanTask(taskDAO *dao.TaskDAO, targetDAO *dao.TargetDAO, resultDAO *dao.ResultDAO, configDAO *dao.ConfigDAO) *FscanTask {
	return &FscanTask{
		TaskTemplate: TaskTemplate{TaskDAO: taskDAO},
		resultDAO:    resultDAO,
		targetDAO:    targetDAO,
		configDAO:    configDAO,
	}
}

// Handle 处理Fscan扫描任务
func (f *FscanTask) Handle(ctx context.Context, t *asynq.Task) error {
	return f.Execute(ctx, t, f.runFscan)
}

// Execute 执行Fscan扫描任务
func (f *FscanTask) Execute(ctx context.Context, t *asynq.Task, handler func(context.Context, *asynq.Task) error) error {
	return f.TaskTemplate.Execute(ctx, t, handler)
}

// runFscan 执行Fscan扫描
func (f *FscanTask) runFscan(ctx context.Context, t *asynq.Task) error {
	var payload struct {
		Host     string `json:"target"`
		TaskID   string `json:"task_id"`
		TargetID string `json:"target_id,omitempty"`
	}

	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("解析任务载荷失败: %v", err)
	}

	if payload.Host == "" {
		return fmt.Errorf("无效的目标地址")
	}

	logging.Info("开始执行 Fscan 扫描任务: %s", payload.Host)

	// 从数据库获取默认工具配置
	toolConfig, err := f.configDAO.GetDefaultToolConfig()
	if err != nil {
		logging.Error("获取默认工具配置失败: %v", err)
		return fmt.Errorf("获取默认工具配置失败: %v", err)
	}

	// 检查 Fscan 是否启用
	if !toolConfig.FscanConfig.Enabled {
		logging.Warn("Fscan 工具未启用，跳过任务执行")
		return nil
	}

	// 创建临时文件来存储 Fscan 结果
	tempDir, err := os.MkdirTemp("", "fscan-results-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "fscan-output.txt")

	// 构建 Fscan 命令基本参数
	fscanArgs := []string{
		"-h", payload.Host,
		"-o", outputFile,
	}

	// 添加端口参数，从配置中读取
	if toolConfig.FscanConfig.Ports != "" {
		fscanArgs = append(fscanArgs, "-p", toolConfig.FscanConfig.Ports)
	}

	// 添加线程数
	if toolConfig.FscanConfig.Threads > 0 {
		fscanArgs = append(fscanArgs, "-t", fmt.Sprintf("%d", toolConfig.FscanConfig.Threads))
	}

	// 添加超时参数
	if toolConfig.FscanConfig.Timeout > 0 {
		fscanArgs = append(fscanArgs, "-timeout", fmt.Sprintf("%d", toolConfig.FscanConfig.Timeout))
	}

	// 添加扫描模式
	if toolConfig.FscanConfig.ScanMode != "" {
		switch toolConfig.FscanConfig.ScanMode {
		case "fast":
			fscanArgs = append(fscanArgs, "-fast")
		case "deep":
			fscanArgs = append(fscanArgs, "-deep")
		}
	}

	// 添加代理参数
	if toolConfig.FscanConfig.Proxy != "" {
		fscanArgs = append(fscanArgs, "-proxy", toolConfig.FscanConfig.Proxy)
	}

	logging.Info("执行 Fscan 命令，参数: %v", fscanArgs)

	// 执行 Fscan 命令
	cmd := exec.CommandContext(ctx, "fscan", fscanArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logging.Error("执行 Fscan 命令失败: %v", err)
		return err
	}

	// 读取结果文件
	resultsData, err := os.ReadFile(outputFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("读取 Fscan 结果文件失败: %v", err)
		}
		logging.Warn("未找到Fscan结果文件")
		resultsData = []byte{}
	}

	// 解析结果
	var ports []PortInfo
	var vulns []VulnInfo
	var webInfo []WebInfo
	var scanTime float64

	lines := strings.Split(string(resultsData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析端口信息
		if strings.Contains(line, "open") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				portStr := strings.Split(parts[1], " ")[0]
				port := 0
				fmt.Sscanf(portStr, "%d", &port)
				ports = append(ports, PortInfo{
					Port:   port,
					Status: "open",
				})
			}
		}

		// 解析漏洞信息
		if strings.HasPrefix(line, "[+]") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 3 {
				vulnType := strings.TrimSpace(parts[1])
				target := strings.TrimSpace(parts[2])
				vulns = append(vulns, VulnInfo{
					Type:        vulnType,
					Target:      target,
					Description: "",
					Severity:    "unknown",
				})
			}
		}

		// 解析Web信息
		if strings.Contains(line, "http") {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				url := parts[0]
				code := 0
				fmt.Sscanf(parts[1], "%d", &code)
				length := 0
				fmt.Sscanf(parts[2], "%d", &length)
				title := ""
				if len(parts) > 3 {
					title = strings.Join(parts[3:], " ")
				}
				webInfo = append(webInfo, WebInfo{
					URL:    url,
					Code:   code,
					Length: length,
					Title:  title,
				})
			}
		}
	}

	// 创建扫描结果
	result := &FscanResult{
		Ports:     ports,
		Vulns:     vulns,
		WebInfo:   webInfo,
		ScanTime:  scanTime,
		Target:    payload.Host,
		Timestamp: time.Now(),
	}

	// 处理 TargetID
	var targetID *primitive.ObjectID
	if payload.TargetID != "" {
		objID, err := primitive.ObjectIDFromHex(payload.TargetID)
		if err == nil {
			targetID = &objID
		}
	}

	// 创建扫描结果记录
	scanResult := &models.Result{
		ID:        primitive.NewObjectID(),
		Type:      "Fscan",
		Target:    payload.Host,
		Timestamp: time.Now(),
		Data:      result,
		TargetID:  targetID,
		IsRead:    false,
	}

	// 保存结果
	if err := f.resultDAO.CreateResult(scanResult); err != nil {
		return fmt.Errorf("failed to save fscan result: %v", err)
	}

	logging.Info("Fscan 任务完成，扫描了 %d 个端口", len(ports))
	return nil
}
