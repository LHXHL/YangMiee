// cmd/yangmiee.go

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"yangmiee/pkg/api"
	"yangmiee/pkg/dao"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/service"
	"yangmiee/pkg/setup"
	"yangmiee/web"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// extractFrontendAssets 提取嵌入的前端资源到本地文件系统
func extractFrontendAssets() {
	// 确保web/dist目录存在
	distDir := "web/dist"
	if err := os.MkdirAll(distDir, 0755); err != nil {
		log.Printf("创建目录%s失败: %v", distDir, err)
		return
	}

	// 检查目录下是否已有index.html文件
	if _, err := os.Stat(filepath.Join(distDir, "index.html")); err == nil {
		// 文件已存在，无需提取
		return
	}

	// 尝试将嵌入的文件复制到本地
	if err := web.CopyToLocalFS(distDir); err != nil {
		log.Printf("提取前端资源失败: %v", err)
	} else {
		log.Printf("前端资源已提取到本地目录: %s", distDir)
	}
}

func main() {
	// 解析命令行参数
	env := flag.String("env", "dev", "运行环境 (dev/prod)")
	flag.Parse()

	// 如果是生产环境，则确保前端资源可用
	if *env == "prod" {
		extractFrontendAssets()
	} else {
		log.Printf("开发环境：前端请求将代理到 http://localhost:8080")
	}

	// 初始化日志系统
	logPath := filepath.Join("logs", "yangmiee.log")
	if err := logging.InitializeLoggers(logPath); err != nil {
		log.Fatalf("初始化日志系统失败: %v", err)
	}
	logging.Info("日志系统初始化成功")

	// 启动日志轮换（每24小时轮换一次）
	logging.StartLogRotation(24 * time.Hour)
	defer logging.StopLogRotation()

	// 创建一个用于优雅关闭的 context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 加载.env文件
	if err := godotenv.Load(); err != nil {
		logging.Error("加载.env文件失败: %v", err)
		return
	}

	// 连接MongoDB数据库
	mongoIp := os.Getenv("MONGODB_IP")
	mongoUsername := os.Getenv("MONGO_INITDB_ROOT_USERNAME")
	mongoPassword := os.Getenv("MONGO_INITDB_ROOT_PASSWORD")
	mongoURI := ""
	// 如果有用户名和密码但没有URI，则构建URI
	if mongoUsername != "" && mongoPassword != "" {
		// 使用docker-compose的mongodb服务
		// mongoURI = fmt.Sprintf("mongodb://%s:%s@mongodb:27017/admin", mongoUsername, mongoPassword)
		mongoURI = fmt.Sprintf("mongodb://%s:%s@%s:27017/admin", mongoUsername, mongoPassword, mongoIp)
	} else {
		// 使用本地的mongodb服务
		mongoURI = "mongodb://localhost:27017"
	}

	client, err := setup.ConnectToMongoDB(mongoURI)
	if err != nil {
		logging.Error("连接MongoDB失败: %v", err)
		return
	}
	defer setup.DisconnectMongoDB(client)
	logging.Info("MongoDB连接成功")

	// 初始化数据库和集合
	db := client.Database("yangmieeDB")

	// 初始化任务相关组件
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		// 使用新的REDIS_IP和REDIS_PORT环境变量
		redisIP := os.Getenv("REDIS_IP")
		redisPort := os.Getenv("REDIS_PORT")

		if redisIP != "" && redisPort != "" {
			redisAddr = fmt.Sprintf("%s:%s", redisIP, redisPort)
		} else {
			redisAddr = "localhost:6379"
		}
	}

	taskService, asynqServer, err := setup.InitTaskComponents(db, redisAddr)
	if err != nil {
		logging.Error("初始化任务组件失败: %v", err)
		return
	}
	defer taskService.Close()

	// 初始化 DAO
	taskDAO := dao.NewTaskDAO(db.Collection("tasks"))
	resultDAO := dao.NewResultDAO(db.Collection("results"))
	userDAO := dao.NewUserDAO(db.Collection("users"))
	configDAO := dao.NewConfigDAO(db.Collection("config"))
	targetDAO := dao.NewTargetDAO(db)

	// 初始化任务处理器
	taskHandler := setup.InitTaskHandler(taskDAO, targetDAO, resultDAO, configDAO)

	// 启动 Asynq 服务器
	setup.StartAsynqServer(asynqServer, taskHandler, redisAddr)

	// 初始化 Service
	jwtSecret := os.Getenv("JWT_SECRET")
	sessionSecret := os.Getenv("SESSION_SECRET")

	userService := service.NewUserService(userDAO, configDAO, jwtSecret)
	configService := service.NewConfigService(configDAO)
	resultService := service.NewResultService(resultDAO)
	dnsService := service.NewDNSService(resultDAO)
	httpxService := service.NewHTTPXService(resultDAO)
	targetService := service.NewTargetService(targetDAO)

	if *env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// 根据环境设置 CORS 配置
	var allowedOrigins []string
	if *env == "prod" {
		allowedOrigins = []string{"*"} // 替换为实际的生产环境域名
	} else {
		allowedOrigins = []string{
			"http://localhost:8080",
			"http://127.0.0.1:8080",
		}
	}

	// 设置API路由，包括任务管理的路由
	router := api.NewRouter(
		userService,
		configService,
		taskService,
		resultService,
		dnsService,
		httpxService,
		targetService,
		jwtSecret,
		sessionSecret,
		allowedOrigins,
		*env, // 将环境变量传递给路由器
	)
	engine := router.SetupRouter()
	logging.Info("API路由设置完成")

	// 日志提示前端集成方式
	if *env == "dev" {
		logging.Info("开发环境：前端请求将代理到 http://localhost:8080")
	} else {
		logging.Info("生产环境：使用嵌入的前端静态文件")
	}

	// 创建 HTTP 服务器
	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "31337"
	}
	serverAddr := ":" + serverPort

	srv := &http.Server{
		Addr:    serverAddr,
		Handler: engine,
	}

	// 在后台启动 HTTP 服务器
	go func() {
		logging.Info("正在启动API服务器在%s...", serverAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error("启动API服务器失败: %v", err)
		}
	}()

	// 设置信号处理
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logging.Info("正在关闭服务器...")

	// 创建一个5秒的超时上下文
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 关闭 HTTP 服务器
	if err := srv.Shutdown(ctx); err != nil {
		logging.Error("服务器强制关闭: %v", err)
	}

	// 关闭 Asynq 服务器
	asynqServer.Shutdown()

	logging.Info("服务器已关闭")
}
