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

// 定义Gogo扫描结果的结构体
type GogoResult struct {
	Ports        []GogoPortInfo `json:"ports"`
	Vulns        []GogoVulnInfo `json:"vulnerabilities"`
	WebInfo      []GogoWebInfo  `json:"web_info"`
	Timestamp    time.Time      `json:"timestamp"`
	Target       string         `json:"target"`
	ScanDuration float64        `json:"scan_duration"`
	ResultFile   string         `json:"result_file"`
}

// GogoPortInfo 表示端口信息
type GogoPortInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Host     string `json:"host"` // 主机地址
	Service  string `json:"service"`
	Status   string `json:"status"`
	Info     string `json:"info,omitempty"`
}

// GogoVulnInfo 表示漏洞信息
type GogoVulnInfo struct {
	Type        string `json:"type"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// GogoWebInfo 表示Web信息
type GogoWebInfo struct {
	URL       string `json:"url"`
	Code      int    `json:"code"`
	Title     string `json:"title"`
	Server    string `json:"server,omitempty"`
	Framework string `json:"framework,omitempty"`
}

// GogoTask 结构体定义Gogo扫描任务
type GogoTask struct {
	TaskTemplate
	resultDAO *dao.ResultDAO
	targetDAO *dao.TargetDAO
	configDAO *dao.ConfigDAO
}

// NewGogoTask 创建一个新的Gogo任务
func NewGogoTask(taskDAO *dao.TaskDAO, targetDAO *dao.TargetDAO, resultDAO *dao.ResultDAO, configDAO *dao.ConfigDAO) *GogoTask {
	return &GogoTask{
		TaskTemplate: TaskTemplate{TaskDAO: taskDAO},
		resultDAO:    resultDAO,
		targetDAO:    targetDAO,
		configDAO:    configDAO,
	}
}

// Handle 处理Gogo扫描任务
func (g *GogoTask) Handle(ctx context.Context, t *asynq.Task) error {
	return g.Execute(ctx, t, g.runGogo)
}

// Execute 执行Gogo扫描任务
func (g *GogoTask) Execute(ctx context.Context, t *asynq.Task, handler func(context.Context, *asynq.Task) error) error {
	return g.TaskTemplate.Execute(ctx, t, handler)
}

// runGogo 执行Gogo扫描
func (g *GogoTask) runGogo(ctx context.Context, t *asynq.Task) error {
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

	logging.Info("开始执行 Gogo 扫描任务: %s", payload.Host)

	// 监听取消信号
	done := make(chan error, 1)
	var cmd *exec.Cmd
	var tempDir string

	// 在协程中执行剩余的工作
	go func() {
		var err error

		// 从数据库获取默认工具配置
		toolConfig, err := g.configDAO.GetDefaultToolConfig()
		if err != nil {
			logging.Error("获取默认工具配置失败: %v", err)
			done <- fmt.Errorf("获取默认工具配置失败: %v", err)
			return
		}

		// 检查 Gogo 是否启用
		if !toolConfig.GogoConfig.Enabled {
			logging.Warn("Gogo 工具未启用，跳过任务执行")
			done <- nil
			return
		}

		// 确保输出目录存在
		outputDir := toolConfig.GogoConfig.OutputPath
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			done <- fmt.Errorf("创建输出目录失败: %v", err)
			return
		}

		// 创建临时文件来存储 Gogo 结果
		tempDir, err = os.MkdirTemp("", "gogo-results-*")
		if err != nil {
			done <- fmt.Errorf("创建临时目录失败: %v", err)
			return
		}

		outputFile := filepath.Join(tempDir, "gogo-result.dat")

		// 构建 Gogo 命令基本参数
		gogoArgs := []string{
			"-i", payload.Host,
		}

		// 添加端口参数
		if toolConfig.GogoConfig.Ports != "" {
			gogoArgs = append(gogoArgs, "-p", toolConfig.GogoConfig.Ports)
		}

		// 添加模式参数
		if toolConfig.GogoConfig.Mode != "" && toolConfig.GogoConfig.Mode != "default" {
			gogoArgs = append(gogoArgs, "-m", toolConfig.GogoConfig.Mode)
		}

		// 添加线程数参数
		if toolConfig.GogoConfig.Thread > 0 {
			gogoArgs = append(gogoArgs, "-t", fmt.Sprintf("%d", toolConfig.GogoConfig.Thread))
		}

		// 添加超时参数
		if toolConfig.GogoConfig.Timeout > 0 {
			gogoArgs = append(gogoArgs, "-d", fmt.Sprintf("%d", toolConfig.GogoConfig.Timeout))
		}

		// 添加漏洞扫描参数
		if toolConfig.GogoConfig.EnableExploit {
			gogoArgs = append(gogoArgs, "-e")
		}

		// 添加主动指纹识别参数
		if toolConfig.GogoConfig.Verbose {
			gogoArgs = append(gogoArgs, "-v")
		}

		// 添加输出文件参数
		gogoArgs = append(gogoArgs, "-f", outputFile)

		logging.Info("执行 Gogo 命令，参数: %v", gogoArgs)

		// 执行 Gogo 命令
		startTime := time.Now()
		cmd = exec.CommandContext(ctx, "gogo", gogoArgs...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// 检查是否是因为取消而失败
			if ctx.Err() == context.Canceled {
				done <- ctx.Err() // 传递取消错误
				return
			}
			logging.Error("执行 Gogo 命令失败: %v, 输出: %s", err, string(output))
			done <- err
			return
		}
		scanDuration := time.Since(startTime).Seconds()

		// 检查结果文件是否存在
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			logging.Error("Gogo 扫描结果文件不存在: %s", outputFile)
			done <- fmt.Errorf("未找到 Gogo 扫描结果文件: %s", outputFile)
			return
		}

		// 将结果文件复制到输出目录
		// 清理目标地址中的非法文件名字符，特别是斜杠 "/"
		cleanTarget := strings.ReplaceAll(payload.Host, "/", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, ":", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, "\\", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, "*", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, "?", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, "\"", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, "<", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, ">", "_")
		cleanTarget = strings.ReplaceAll(cleanTarget, "|", "_")

		resultFileName := fmt.Sprintf("gogo-scan-%s-%s.dat",
			cleanTarget,
			time.Now().Format("20060102-150405"))
		permanentResultPath := filepath.Join(outputDir, resultFileName)

		resultData, err := os.ReadFile(outputFile)
		if err != nil {
			logging.Error("读取 Gogo 结果文件失败: %v", err)
			done <- fmt.Errorf("读取 Gogo 结果文件失败: %v", err)
			return
		}

		if err := os.WriteFile(permanentResultPath, resultData, 0644); err != nil {
			logging.Error("保存 Gogo 结果文件到输出目录失败: %v", err)
			done <- fmt.Errorf("保存 Gogo 结果文件到输出目录失败: %v", err)
			return
		}

		logging.Info("Gogo 结果已保存到: %s", permanentResultPath)

		// 解析结果文件为结构化数据
		// 执行 gogo -F file.dat 命令来查看结果
		viewCmd := exec.Command("gogo", "-F", outputFile)
		viewResult, err := viewCmd.Output()
		if err != nil {
			logging.Error("读取Gogo结果文件失败: %v", err)
			done <- fmt.Errorf("读取Gogo结果文件失败: %v", err)
			return
		}

		// 去除ANSI颜色代码
		// ANSI颜色代码的正则表达式模式: \x1b\[[0-9;]*m
		resultText := string(viewResult)
		resultText = removeANSIColor(resultText)

		// 解析结果数据
		var ports []GogoPortInfo
		var vulns []GogoVulnInfo
		var webInfo []GogoWebInfo

		lines := strings.Split(resultText, "\n")
		currentHost := payload.Host

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// 检查是否为新主机的开始
			if strings.HasPrefix(line, "[+]") {
				hostLine := strings.TrimPrefix(line, "[+]")
				hostParts := strings.Fields(hostLine)
				if len(hostParts) > 0 {
					currentHost = strings.TrimSpace(hostParts[0])
				}
				continue
			}

			// 解析端口信息 - 所有类型的端口
			if strings.Contains(line, "://") {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					protocolFull := parts[0]
					protocolParts := strings.Split(protocolFull, "://")

					if len(protocolParts) == 2 {
						protocol := protocolParts[0]
						hostPort := strings.Split(protocolParts[1], ":")

						if len(hostPort) >= 2 {
							host := hostPort[0]
							port := 0
							fmt.Sscanf(hostPort[1], "%d", &port)

							service := ""
							info := ""
							status := "open"

							// 提取服务和其他信息
							if len(parts) >= 2 {
								service = parts[1]
							}

							// 构建额外信息字段
							if len(parts) >= 3 {
								info = strings.Join(parts[2:], " ")
							}

							// 提取状态信息
							if strings.Contains(line, "[open]") {
								status = "open"
							}

							// 添加协议特定处理
							if protocol == "http" || protocol == "https" {
								// 对于HTTP/HTTPS端口, 我们既要添加端口信息，也要添加Web信息
								portInfo := GogoPortInfo{
									Protocol: protocol,
									Port:     port,
									Host:     host,
									Service:  service,
									Status:   status,
									Info:     info,
								}
								ports = append(ports, portInfo)

								// Web信息处理在下面的专门解析HTTP部分
							} else {
								// 其他协议端口
								portInfo := GogoPortInfo{
									Protocol: protocol,
									Port:     port,
									Host:     host,
									Service:  service,
									Status:   status,
									Info:     info,
								}
								ports = append(ports, portInfo)
							}
						}
					}
				}
			}

			// 解析Web信息 - HTTP/HTTPS服务
			if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					url := parts[0]
					server := ""
					framework := ""
					code := 0
					title := ""

					// 尝试解析服务器信息
					if len(parts) >= 2 {
						server = parts[1]
					}

					// 尝试解析框架信息 - 通常包含在第三个位置或者中间部分
					frameworks := []string{}
					for i := 2; i < len(parts); i++ {
						// 跳过包含状态码的部分
						if strings.HasPrefix(parts[i], "[") && strings.HasSuffix(parts[i], "]") {
							continue
						}

						// 收集可能的框架信息
						if !strings.HasPrefix(parts[i], "[") && i < len(parts)-1 {
							if strings.Contains(parts[i], "||") {
								frameworkItems := strings.Split(parts[i], "||")
								frameworks = append(frameworks, frameworkItems...)
							} else {
								frameworks = append(frameworks, parts[i])
							}
						}
					}

					if len(frameworks) > 0 {
						framework = strings.Join(frameworks, ",")
					}

					// 尝试解析状态码和标题
					for i, part := range parts {
						if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
							codeStr := strings.Trim(part, "[]")
							fmt.Sscanf(codeStr, "%d", &code)

							// 尝试获取标题 - 通常在状态码之后
							if i+1 < len(parts) {
								title = strings.Join(parts[i+1:], " ")
								break
							}
						}
					}

					webInfo = append(webInfo, GogoWebInfo{
						URL:       url,
						Code:      code,
						Title:     title,
						Server:    server,
						Framework: framework,
					})
				}
			}

			// 解析漏洞信息
			if strings.Contains(line, "high:") || strings.Contains(line, "medium:") || strings.Contains(line, "low:") || strings.Contains(line, "info:") {
				severity := "unknown"
				vulnType := ""

				if strings.Contains(line, "high:") {
					severity = "high"
					vulnType = "high"
				} else if strings.Contains(line, "medium:") {
					severity = "medium"
					vulnType = "medium"
				} else if strings.Contains(line, "low:") {
					severity = "low"
					vulnType = "low"
				} else if strings.Contains(line, "info:") {
					severity = "info"
					vulnType = "info"
				}

				// 获取相关联的目标和端口信息
				targetWithPort := currentHost // 默认使用当前主机作为目标
				vulnDescription := ""

				// 在当前行中查找目标信息 - 通常在行的开头或漏洞描述中
				// 格式可能是 protocol://host:port
				for _, part := range strings.Fields(line) {
					if strings.Contains(part, "://") && strings.Contains(part, ":") {
						parts := strings.Split(part, "://")
						if len(parts) == 2 {
							hostPort := strings.Split(parts[1], ":")
							if len(hostPort) >= 2 {
								// 这是一个完整的服务地址
								targetWithPort = part
								break
							}
						}
					}
				}

				// 如果没有找到完整地址，但有服务名相关信息，构造更完整的目标描述
				if !strings.Contains(targetWithPort, "://") {
					// 检查是否有服务名提示
					serviceKeywords := map[string]string{
						"redis":    "redis://",
						"mysql":    "mysql://",
						"ssh":      "ssh://",
						"mongodb":  "mongodb://",
						"postgres": "postgresql://",
						"oracle":   "oracle://",
						"mssql":    "mssql://",
						"ftp":      "ftp://",
						"telnet":   "telnet://",
						"smb":      "smb://",
						"rdp":      "rdp://",
						"vnc":      "vnc://",
					}

					for keyword, protocol := range serviceKeywords {
						if strings.Contains(strings.ToLower(line), keyword) {
							// 找到服务类型，构造更完整的目标地址
							targetWithPort = protocol + targetWithPort
							break
						}
					}
				}

				// 提取漏洞名称 - 通常在 high:/medium:/low:/info: 后面
				if strings.Contains(line, "high:") {
					parts := strings.SplitN(line, "high:", 2)
					if len(parts) == 2 {
						vulnDescription = extractVulnName(parts[1])
					}
				} else if strings.Contains(line, "medium:") {
					parts := strings.SplitN(line, "medium:", 2)
					if len(parts) == 2 {
						vulnDescription = extractVulnName(parts[1])
					}
				} else if strings.Contains(line, "low:") {
					parts := strings.SplitN(line, "low:", 2)
					if len(parts) == 2 {
						vulnDescription = extractVulnName(parts[1])
					}
				} else if strings.Contains(line, "info:") {
					parts := strings.SplitN(line, "info:", 2)
					if len(parts) == 2 {
						vulnDescription = extractVulnName(parts[1])
					}
				}

				// 如果没有找到漏洞名称，尝试使用通用方法提取
				if vulnDescription == "" {
					// 查找常见的漏洞命名模式，如 xxx_unauthorized 或 xxx_unauth
					for _, word := range strings.Fields(line) {
						if strings.Contains(word, "_unauthorized") ||
							strings.Contains(word, "_unauth") ||
							strings.Contains(word, "_weakpass") ||
							strings.Contains(word, "_default_credential") {
							vulnDescription = strings.TrimSpace(word)
							break
						}
					}
				}

				// 如果仍然没有找到漏洞名称，使用部分原始描述
				if vulnDescription == "" {
					if strings.Contains(line, "payloads:") {
						// 提取服务名 + vulnerable 作为漏洞描述
						for _, serviceName := range []string{"redis", "mysql", "mongodb", "postgres", "oracle", "mssql", "elasticsearch", "ssh", "ftp", "smb", "rdp", "vnc"} {
							if strings.Contains(strings.ToLower(line), serviceName) {
								vulnDescription = serviceName + "_vulnerable"
								break
							}
						}

						// 如果没有匹配到具体服务，使用一般描述
						if vulnDescription == "" {
							vulnDescription = "potential_vulnerability"
						}
					} else {
						// 从原始行中提取一些有意义的部分作为描述
						for _, keyword := range []string{"vuln", "auth", "weak", "default", "cve", "overflow", "injection"} {
							if strings.Contains(strings.ToLower(line), keyword) {
								index := strings.Index(strings.ToLower(line), keyword)
								startPos := max(0, index-10)
								endPos := min(len(line), index+20)
								vulnDescription = "potential_" + strings.TrimSpace(strings.ToLower(line[startPos:endPos]))
								// 替换空格为下划线，标准化漏洞名称格式
								vulnDescription = strings.ReplaceAll(vulnDescription, " ", "_")
								break
							}
						}
					}
				}

				// 如果仍然没有找到合适的描述，使用安全级别作为基本描述
				if vulnDescription == "" {
					vulnDescription = fmt.Sprintf("%s_severity_vulnerability", severity)
				}

				vulns = append(vulns, GogoVulnInfo{
					Type:        vulnType,
					Target:      targetWithPort,
					Description: vulnDescription,
					Severity:    severity,
				})
			}
		}

		// 处理 TargetID
		var targetID *primitive.ObjectID
		if payload.TargetID != "" {
			objID, err := primitive.ObjectIDFromHex(payload.TargetID)
			if err == nil {
				targetID = &objID
			}
		}

		// 创建结果对象
		gogoResult := &GogoResult{
			Ports:        ports,
			Vulns:        vulns,
			WebInfo:      webInfo,
			Timestamp:    time.Now(),
			Target:       payload.Host,
			ScanDuration: scanDuration,
			ResultFile:   permanentResultPath,
		}

		// 创建扫描结果记录
		scanResult := &models.Result{
			ID:        primitive.NewObjectID(),
			Type:      "Gogo",
			Target:    payload.Host,
			Timestamp: time.Now(),
			Data:      gogoResult,
			TargetID:  targetID,
			IsRead:    false,
		}

		// 存储扫描结果
		if err := g.resultDAO.CreateResult(scanResult); err != nil {
			logging.Error("存储扫描结果失败: %v", err)
			done <- err
			return
		}

		logging.Info("成功处理并存储 Gogo 结果，发现 %d 个端口, %d 个漏洞, %d 个Web应用",
			len(ports), len(vulns), len(webInfo))
		done <- nil
	}()

	// 等待任务完成或被取消
	select {
	case err := <-done:
		// 任务完成或出错
		if tempDir != "" {
			os.RemoveAll(tempDir)
		}
		return err
	case <-ctx.Done():
		// 上下文被取消
		logging.Info("Gogo 任务被取消: %s", payload.Host)
		return ctx.Err()
	}
}

// removeANSIColor 去除字符串中的ANSI颜色控制码
func removeANSIColor(str string) string {
	// 简单替换方法：替换常见的ANSI转义序列
	result := str

	// 常见ANSI颜色代码模式: ESC[ ... m
	// ESC 是 ASCII 码 27 (十六进制 0x1B)

	// 替换所有格式为 ESC[...m 的ANSI转义序列
	// 使用状态机方式查找和替换
	var sb strings.Builder
	inEscSeq := false

	for i := 0; i < len(result); i++ {
		c := result[i]

		if c == 0x1B { // ESC 字符
			inEscSeq = true
			continue
		}

		if inEscSeq {
			if c == '[' {
				// 继续在转义序列中
				continue
			} else if (c >= '0' && c <= '9') || c == ';' {
				// 数字或分号，仍在转义序列中
				continue
			} else if c == 'm' {
				// 转义序列结束
				inEscSeq = false
				continue
			} else {
				// 不是标准ANSI颜色序列，恢复正常处理
				inEscSeq = false
				sb.WriteByte(c)
			}
		} else {
			// 普通字符
			sb.WriteByte(c)
		}
	}

	return sb.String()
}

// extractVulnName 从漏洞描述文本中提取漏洞名称
func extractVulnName(text string) string {
	text = strings.TrimSpace(text)

	// 优先匹配常见的漏洞命名模式
	patterns := []string{
		"_unauthorized", "_unauth",
		"_weak_password", "_default_password",
		"_rce", "_lfi", "_sqli", "_xss",
		"_csrf", "_ssrf", "_xxe",
	}

	// 查找这些模式
	for _, pattern := range patterns {
		index := strings.Index(strings.ToLower(text), pattern)
		if index > 0 {
			// 找到前面的单词边界
			start := index
			for start > 0 && (text[start-1] == '_' || (text[start-1] >= 'a' && text[start-1] <= 'z') || (text[start-1] >= 'A' && text[start-1] <= 'Z') || (text[start-1] >= '0' && text[start-1] <= '9')) {
				start--
			}

			// 找到后面的单词边界
			end := index + len(pattern)
			for end < len(text) && (text[end] == '_' || (text[end] >= 'a' && text[end] <= 'z') || (text[end] >= 'A' && text[end] <= 'Z') || (text[end] >= '0' && text[end] <= '9')) {
				end++
			}

			return strings.TrimSpace(text[start:end])
		}
	}

	// 如果没有匹配到标准模式，检查是否有CVE编号
	if strings.Contains(strings.ToUpper(text), "CVE-") {
		// 提取CVE编号
		start := strings.Index(strings.ToUpper(text), "CVE-")
		if start >= 0 {
			end := start + 12 // 大致CVE编号长度 CVE-YYYY-NNNNN
			if end > len(text) {
				end = len(text)
			}
			return strings.TrimSpace(text[start:end])
		}
	}

	// 如果没有标准匹配，返回开头部分作为描述
	words := strings.Fields(text)
	if len(words) >= 3 {
		return strings.Join(words[:3], " ")
	} else if len(words) > 0 {
		return strings.Join(words, " ")
	}

	return text
}

// max 返回两个整数中的较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
