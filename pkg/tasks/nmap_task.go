package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/models"

	"encoding/xml"

	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type NmapTask struct {
	TaskTemplate
	resultDAO *dao.ResultDAO
	targetDAO *dao.TargetDAO
	configDAO *dao.ConfigDAO
}

func NewNmapTask(taskDAO *dao.TaskDAO, targetDAO *dao.TargetDAO, resultDAO *dao.ResultDAO, configDAO *dao.ConfigDAO) *NmapTask {
	return &NmapTask{
		TaskTemplate: TaskTemplate{TaskDAO: taskDAO},
		resultDAO:    resultDAO,
		targetDAO:    targetDAO,
		configDAO:    configDAO,
	}
}

func (n *NmapTask) Handle(ctx context.Context, t *asynq.Task) error {
	return n.Execute(ctx, t, n.runNmap)
}

func (n *NmapTask) runNmap(ctx context.Context, t *asynq.Task) error {
	var payload struct {
		Host     string `json:"target"`
		TaskID   string `json:"task_id"`
		TargetID string `json:"target_id,omitempty"`
	}

	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("解析任务载荷失败: %v", err)
	}

	if payload.Host == "" {
		return fmt.Errorf("无效的主机地址")
	}

	logging.Info("开始执行 Nmap 任务: %s", payload.Host)

	// 监听取消信号
	done := make(chan error, 1)
	var cmd *exec.Cmd
	var tempFile *os.File

	// 在协程中执行剩余的工作
	go func() {
		var err error

		// 从数据库获取默认工具配置
		toolConfig, err := n.configDAO.GetDefaultToolConfig()
		if err != nil {
			logging.Error("获取默认工具配置失败: %v", err)
			done <- fmt.Errorf("获取默认工具配置失败: %v", err)
			return
		}

		// 检查 Nmap 是否启用
		if !toolConfig.NmapConfig.Enabled {
			logging.Warn("Nmap 工具未启用，跳过任务执行")
			done <- nil
			return
		}

		// 创建临时文件来存储 Nmap 结果
		tempFile, err = os.CreateTemp("", "nmap-result-*.xml")
		if err != nil {
			done <- fmt.Errorf("创建临时文件失败: %v", err)
			return
		}
		tempFile.Close()

		// 构建 Nmap 命令基本参数
		nmapArgs := []string{
			"-n", "--resolve-all", "-Pn",
			"--min-hostgroup", "64",
			"--max-retries", "0",
			"-oX", tempFile.Name(),
			"--version-intensity", "9",
		}

		// 添加端口参数，如果配置中有指定
		if toolConfig.NmapConfig.Ports != "" {
			nmapArgs = append(nmapArgs, "-p", toolConfig.NmapConfig.Ports)
		}

		// 添加超时参数，如果配置中有指定
		if toolConfig.NmapConfig.ScanTimeout > 0 {
			timeout := fmt.Sprintf("%dm", toolConfig.NmapConfig.ScanTimeout/60)
			nmapArgs = append(nmapArgs, "--host-timeout", timeout)
			nmapArgs = append(nmapArgs, "--script-timeout", "3m")
		} else {
			nmapArgs = append(nmapArgs, "--host-timeout", "10m")
			nmapArgs = append(nmapArgs, "--script-timeout", "3m")
		}

		// 添加并发参数，如果配置中有指定
		if toolConfig.NmapConfig.Concurrency > 0 {
			nmapArgs = append(nmapArgs, "--min-rate", fmt.Sprintf("%d", toolConfig.NmapConfig.Concurrency))
		} else {
			nmapArgs = append(nmapArgs, "--min-rate", "10000")
		}

		nmapArgs = append(nmapArgs, "-T4", payload.Host)

		logging.Info("执行 Nmap 命令，参数: %v", nmapArgs)

		// 执行 Nmap 命令，使用上下文以支持取消
		cmd = exec.CommandContext(ctx, "nmap", nmapArgs...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// 检查是否是因为取消而失败
			if ctx.Err() == context.Canceled {
				done <- ctx.Err() // 传递取消错误
				return
			}
			done <- fmt.Errorf("执行 Nmap 命令失败: %v, 输出: %s", err, string(output))
			return
		}

		// 读取 XML 结果
		xmlData, err := os.ReadFile(tempFile.Name())
		if err != nil {
			done <- fmt.Errorf("读取 Nmap 结果文件失败: %v", err)
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

		// 解析 XML 结果
		portEntries, err := parseNmapXML(xmlData, targetID)
		if err != nil {
			done <- fmt.Errorf("解析 Nmap XML 结果失败: %v", err)
			return
		}

		portData := &models.PortData{
			Ports: portEntries,
		}

		scanResult := &models.Result{
			ID:        primitive.NewObjectID(),
			Type:      "Port",
			Target:    payload.Host,
			Timestamp: time.Now(),
			Data:      portData,
			TargetID:  targetID,
			IsRead:    false,
		}

		if err := n.resultDAO.CreateResult(scanResult); err != nil {
			logging.Error("存储扫描结果失败: %v", err)
			done <- err
			return
		}

		logging.Info("Nmap 任务完成，扫描了 %d 个端口", len(portEntries))
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
		logging.Info("Nmap 任务被取消: %s", payload.Host)
		return ctx.Err()
	}
}

// parseNmapXML 函数保持不变
func parseNmapXML(data []byte, targetID *primitive.ObjectID) ([]models.PortEntry, error) {
	var result struct {
		Hosts []struct {
			Addresses []struct {
				Addr     string `xml:"addr,attr"`
				AddrType string `xml:"addrtype,attr"`
			} `xml:"address"`
			Ports []struct {
				ID       int    `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Version   string `xml:"version,attr"`
					ExtraInfo string `xml:"extrainfo,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}

	if err := xml.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	var portEntries []models.PortEntry
	for _, host := range result.Hosts {
		// 获取主机 IP 地址
		var hostAddr string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				hostAddr = addr.Addr
				break
			}
		}

		if hostAddr == "" && len(host.Addresses) > 0 {
			hostAddr = host.Addresses[0].Addr
		}

		for _, port := range host.Ports {
			entry := models.PortEntry{
				ID:         primitive.NewObjectID(),
				Host:       hostAddr,
				Number:     port.ID,
				Protocol:   port.Protocol,
				State:      port.State.State,
				Service:    port.Service.Name,
				IsRead:     false,
				HTTPStatus: 0,
				HTTPTitle:  "",
			}

			// 如果有目标ID，则设置它
			if targetID != nil {
				entry.TargetID = targetID
			}

			portEntries = append(portEntries, entry)
		}
	}

	return portEntries, nil
}
