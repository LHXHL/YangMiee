package api

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"yangmiee/pkg/api/handlers"
	"yangmiee/pkg/logging"
	"yangmiee/pkg/middleware"
	"yangmiee/pkg/service"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const (
	// 开发环境前端服务器地址
	devFrontendURL = "http://localhost:8080"
)

// 定义API路径前缀，用于判断请求是API还是前端
var apiPathPrefixes = []string{
	"/auth/",
	"/system/",
	"/tools/",
	"/users",
	"/tasks",
	"/targets",
	"/results",
}

// Router 路由器结构体
type Router struct {
	userHandler    *handlers.UserHandler
	configHandler  *handlers.ConfigHandler
	taskHandler    *handlers.TaskHandler
	resultHandler  *handlers.ResultHandler
	targetHandler  *handlers.TargetHandler
	jwtSecret      string
	sessionSecret  string
	allowedOrigins []string
	env            string
}

// NewRouter 创建新的路由器
func NewRouter(
	userService *service.UserService,
	configService *service.ConfigService,
	taskService *service.TaskService,
	resultService *service.ResultService,
	dnsService *service.DNSService,
	httpxService *service.HTTPXService,
	targetService *service.TargetService,
	jwtSecret string,
	sessionSecret string,
	allowedOrigins []string,
	env string,
) *Router {
	return &Router{
		userHandler:    handlers.NewUserHandler(userService),
		configHandler:  handlers.NewConfigHandler(configService),
		taskHandler:    handlers.NewTaskHandler(taskService),
		resultHandler:  handlers.NewResultHandler(resultService, dnsService, httpxService),
		targetHandler:  handlers.NewTargetHandler(targetService),
		jwtSecret:      jwtSecret,
		sessionSecret:  sessionSecret,
		allowedOrigins: allowedOrigins,
		env:            env,
	}
}

// SetupRouter 设置并返回 gin.Engine
func (r *Router) SetupRouter() *gin.Engine {
	router := gin.Default()

	// 配置安全相关中间件
	r.setupSecurityMiddleware(router)

	// 设置API路由
	r.setupAPIRoutes(router)

	// 设置前端资源处理
	r.setupFrontendHandler(router)

	return router
}

// setupSecurityMiddleware 设置安全相关中间件
func (r *Router) setupSecurityMiddleware(router *gin.Engine) {
	// 配置CORS中间件
	router.Use(cors.New(cors.Config{
		AllowOrigins:     r.allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 设置Session中间件
	store := cookie.NewStore([]byte(r.sessionSecret))
	router.Use(sessions.Sessions("mysession", store))

	// 添加安全头中间件
	router.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		if r.env == "prod" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	})
}

// setupAPIRoutes 设置API路由
func (r *Router) setupAPIRoutes(router *gin.Engine) {
	// 不需要认证的API
	r.setupPublicAPIRoutes(router)

	// 需要认证的API
	authenticated := router.Group("/")
	authenticated.Use(middleware.AuthMiddleware(r.jwtSecret))
	r.setupAuthenticatedAPIRoutes(authenticated)
}

// setupPublicAPIRoutes 设置公开API路由
func (r *Router) setupPublicAPIRoutes(router *gin.Engine) {
	// 验证JWT的API
	router.GET("/auth/check", r.userHandler.CheckAuth)
	router.GET("/auth/qrcode", r.userHandler.GenerateQRCode)
	router.POST("/auth/validate", r.userHandler.ValidateTOTP)
}

// setupAuthenticatedAPIRoutes 设置需要认证的API路由
func (r *Router) setupAuthenticatedAPIRoutes(group *gin.RouterGroup) {
	// 控制二维码接口状态的API
	group.GET("/auth/qrcode/status", r.configHandler.GetQRCodeStatus)
	group.POST("/auth/qrcode/status", r.configHandler.SetQRCodeStatus)
	group.POST("/auth/logout", r.userHandler.Logout)

	// 系统配置相关API
	group.GET("/system/info", r.configHandler.GetSystemInfo)
	group.GET("/system/tools", r.configHandler.GetToolsStatus)

	// 工具配置相关API
	tools := group.Group("/tools")
	{
		tools.GET("/configs", r.configHandler.GetToolConfigs)
		tools.GET("/configs/default", r.configHandler.GetDefaultToolConfig)
		tools.GET("/configs/:id", r.configHandler.GetToolConfigByID)
		tools.POST("/configs", r.configHandler.CreateToolConfig)
		tools.PUT("/configs/:id", r.configHandler.UpdateToolConfig)
		tools.DELETE("/configs/:id", r.configHandler.DeleteToolConfig)
		tools.PUT("/configs/:id/default", r.configHandler.SetDefaultToolConfig)
	}

	// 用户管理API
	users := group.Group("/users")
	{
		users.GET("", r.userHandler.GetUsers)
		users.GET("/:account", r.userHandler.GetUser)
		users.POST("", r.userHandler.CreateUser)
		users.DELETE("", r.userHandler.DeleteUsers)
	}

	// 任务管理API
	tasks := group.Group("/tasks")
	{
		tasks.POST("", r.taskHandler.CreateTask)
		tasks.GET("", r.taskHandler.GetAllTasks)
		tasks.DELETE("", r.taskHandler.DeleteTasks)
		tasks.POST("/start", r.taskHandler.StartTasks)
		tasks.POST("/stop", r.taskHandler.StopTasks)
	}

	// 目标管理API
	targets := group.Group("/targets")
	{
		targets.POST("", r.targetHandler.CreateTarget)
		targets.GET("", r.targetHandler.GetAllTargets)
		targets.GET("/:id", r.targetHandler.GetTargetByID)
		targets.PUT("/:id", r.targetHandler.UpdateTarget)
		targets.DELETE("/:id", r.targetHandler.DeleteTarget)
		targets.GET("/:id/details", r.targetHandler.GetTargetDetails)
	}

	// 扫描结果管理API
	results := group.Group("/results")
	{
		results.GET("/:id", r.resultHandler.GetResultByID)
		results.POST("/:id", r.resultHandler.GetResultByIDWithPagination)
		results.GET("/type/:type", r.resultHandler.GetResultsByType)
		results.POST("/type/:type", r.resultHandler.GetResultsByTypeWithPagination)
		results.PUT("/:id", r.resultHandler.UpdateResult)
		results.DELETE("/:id", r.resultHandler.DeleteResult)
		results.PUT("/:id/read", r.resultHandler.MarkResultAsRead)
		results.PUT("/:id/entries/:entry_id/read", r.resultHandler.MarkEntryAsRead)
		results.PUT("/:id/entries/resolve", r.resultHandler.ResolveSubdomainIPHandler)
		results.PUT("/:id/entries/probe", r.resultHandler.ProbeHandler)
	}
}

// setupFrontendHandler 根据环境设置前端资源处理
func (r *Router) setupFrontendHandler(router *gin.Engine) {
	if r.env == "dev" {
		logging.Info("开发环境：前端代理到 %s", devFrontendURL)
		r.setupDevModeFrontend(router)
	} else {
		logging.Info("生产环境：使用嵌入的静态文件")
		r.setupProdModeFrontend(router)
	}
}

// setupDevModeFrontend 为开发环境设置前端处理
func (r *Router) setupDevModeFrontend(router *gin.Engine) {
	fmt.Println("开发环境：前端代理到", devFrontendURL)

	// 创建反向代理
	frontendURL, _ := url.Parse(devFrontendURL)
	proxy := httputil.NewSingleHostReverseProxy(frontendURL)

	// 配置反向代理以保留原始请求路径
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
	}

	// 处理代理错误
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logging.Error("前端代理错误: %v", err)
		http.Error(w, "前端服务不可用，请确认开发服务器是否启动", http.StatusBadGateway)
	}

	// 处理任何非API请求
	router.NoRoute(func(c *gin.Context) {
		if !isAPIPath(c.Request.URL.Path) {
			logging.Debug("开发模式：代理请求到前端 %s", c.Request.URL.Path)
			proxy.ServeHTTP(c.Writer, c.Request)
			return
		}

		// API 404错误，记录日志
		logging.Warn("API路径未找到: %s %s", c.Request.Method, c.Request.URL.Path)
		c.JSON(http.StatusNotFound, gin.H{"error": "API路径未找到"})
	})
}

// setupProdModeFrontend 为生产环境设置前端处理
func (r *Router) setupProdModeFrontend(router *gin.Engine) {
	staticDir := "web/dist"

	// 设置静态资源
	router.StaticFile("/", filepath.Join(staticDir, "index.html"))
	router.StaticFile("/favicon.ico", filepath.Join(staticDir, "favicon.ico"))
	router.StaticFS("/assets", http.Dir(filepath.Join(staticDir, "assets")))

	// 额外处理带/auth前缀的静态资源请求
	router.StaticFile("/auth/favicon.ico", filepath.Join(staticDir, "favicon.ico"))
	router.StaticFS("/auth/assets", http.Dir(filepath.Join(staticDir, "assets")))

	// 处理其他路由
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// 处理API路径
		if isAPIPath(path) {
			logging.Warn("API路径未找到: %s %s", c.Request.Method, path)
			c.JSON(http.StatusNotFound, gin.H{"error": "API路径未找到"})
			return
		}

		// 非API路径的GET请求，提供SPA页面
		if c.Request.Method == http.MethodGet {
			// 移除可能的/auth前缀
			if strings.HasPrefix(path, "/auth") && path != "/auth" {
				redirectPath := strings.TrimPrefix(path, "/auth")
				if redirectPath == "" {
					redirectPath = "/"
				}
				logging.Debug("重定向 %s 到 %s", path, redirectPath)
				c.Redirect(http.StatusMovedPermanently, redirectPath)
				return
			}

			logging.Debug("提供SPA页面: %s", path)
			c.File(filepath.Join(staticDir, "index.html"))
			return
		}

		// 其他请求方法返回404
		logging.Warn("未找到资源: %s %s", c.Request.Method, path)
		c.JSON(http.StatusNotFound, gin.H{"error": "资源未找到"})
	})
}

// isAPIPath 判断路径是否为API路径
func isAPIPath(path string) bool {
	// 排除静态资源路径
	if strings.HasPrefix(path, "/assets") ||
		strings.HasPrefix(path, "/favicon.ico") ||
		(strings.HasPrefix(path, "/auth/assets") ||
			strings.HasPrefix(path, "/auth/favicon.ico")) {
		return false
	}

	// 判断是否为API前缀
	for _, prefix := range apiPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
