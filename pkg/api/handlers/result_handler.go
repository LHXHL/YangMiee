package handlers

import (
	"net/http"
	"strconv"
	"time"
	"yangmiee/pkg/models"
	"yangmiee/pkg/service"

	"github.com/gin-gonic/gin"
)

type ResultHandler struct {
	resultService *service.ResultService
	dnsService    *service.DNSService
	httpxService  *service.HTTPXService
}

// NewResultHandler 创建一个新的 ResultHandler 实例
func NewResultHandler(resultService *service.ResultService, dnsService *service.DNSService, httpxService *service.HTTPXService) *ResultHandler {
	return &ResultHandler{
		resultService: resultService,
		dnsService:    dnsService,
		httpxService:  httpxService,
	}
}

// CreateResult 处理创建扫描结果的请求
func (h *ResultHandler) CreateResult(c *gin.Context) {
	var request struct {
		Type    string      `json:"type" binding:"required"`
		Payload interface{} `json:"payload" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}

	result := &models.Result{
		Type:      request.Type,
		Timestamp: time.Now(),
		Data:      request.Payload,
	}

	if err := h.resultService.CreateResult(result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建扫描结果失败"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "扫描结果创建成功"})
}

// GetResultByID 根据 ID 获取单个扫描结果
func (h *ResultHandler) GetResultByID(c *gin.Context) {
	id := c.Param("id")

	// 检查是否有分页参数，如果有，表示要分页查询条目
	pageStr := c.Query("page")
	pageSizeStr := c.Query("pageSize")

	if pageStr != "" || pageSizeStr != "" {
		// 有分页参数，按分页处理
		// 仅解析分页参数，但当前实现中不使用，预留给未来处理条目分页
		_, _ = strconv.Atoi(pageStr)     // 忽略解析错误，仅做占位
		_, _ = strconv.Atoi(pageSizeStr) // 忽略解析错误，仅做占位

		// 这里调用对应的服务方法获取分页数据
		// 为了保持接口一致性，这里暂时还是返回完整结果
		result, err := h.resultService.GetResultByID(id)
		if err != nil {
			if err.Error() == "result not found" {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到该扫描结果"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "获取扫描结果失败"})
			}
			return
		}

		c.JSON(http.StatusOK, result)
		return
	}

	// 无分页参数，按原方式处理
	result, err := h.resultService.GetResultByID(id)
	if err != nil {
		if err.Error() == "result not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "未找到该扫描结果"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取扫描结果失败"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetResultByIDWithPagination 根据 ID 获取单个扫描结果（使用 JSON 参数格式）
func (h *ResultHandler) GetResultByIDWithPagination(c *gin.Context) {
	id := c.Param("id")

	// 解析分页参数
	var request struct {
		Page     int `json:"page"`
		PageSize int `json:"pageSize"`
	}

	// 使用 JSON 解析请求体
	if err := c.ShouldBindJSON(&request); err != nil {
		// 参数错误使用默认值
		request.Page = 1
		request.PageSize = 10
	}

	// 验证分页参数
	if request.Page < 1 {
		request.Page = 1
	}
	if request.PageSize < 1 {
		request.PageSize = 10
	}

	// 调用服务方法获取结果（暂时忽略分页参数，返回完整结果）
	// 这部分可以在未来扩展为支持条目的分页功能
	result, err := h.resultService.GetResultByID(id)
	if err != nil {
		if err.Error() == "result not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "未找到该扫描结果"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取扫描结果失败"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetResultsByType 根据类型获取扫描结果列表（全部）
func (h *ResultHandler) GetResultsByType(c *gin.Context) {
	resultType := c.Param("type")

	// 检查是否有分页参数
	pageStr := c.Query("page")
	pageSizeStr := c.Query("pageSize")

	// 如果存在分页参数，使用分页查询
	if pageStr != "" || pageSizeStr != "" {
		page := 1
		pageSize := 10

		// 解析页码
		if pageStr != "" {
			if pageVal, err := strconv.Atoi(pageStr); err == nil && pageVal > 0 {
				page = pageVal
			}
		}

		// 解析每页数量
		if pageSizeStr != "" {
			if pageSizeVal, err := strconv.Atoi(pageSizeStr); err == nil && pageSizeVal > 0 {
				pageSize = pageSizeVal
			}
		}

		// 使用分页方法查询
		results, _, err := h.resultService.GetResultsByTypeWithPagination(resultType, page, pageSize)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取该类型的扫描结果"})
			return
		}

		c.JSON(http.StatusOK, results)
		return
	}

	// 无分页参数，获取全部结果
	results, err := h.resultService.GetResultsByType(resultType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取该类型的扫描结果"})
		return
	}

	c.JSON(http.StatusOK, results)
}

// GetResultsByTypeWithPagination 根据类型获取扫描结果列表（分页）
func (h *ResultHandler) GetResultsByTypeWithPagination(c *gin.Context) {
	resultType := c.Param("type")

	// 解析分页参数
	var request struct {
		Page     int `json:"page"`
		PageSize int `json:"pageSize"`
	}

	// 使用 JSON 解析请求体
	if err := c.ShouldBindJSON(&request); err != nil {
		// 参数错误使用默认值
		request.Page = 1
		request.PageSize = 10
	}

	// 验证分页参数
	if request.Page < 1 {
		request.Page = 1
	}
	if request.PageSize < 1 {
		request.PageSize = 10
	}

	// 使用分页方法查询
	results, _, err := h.resultService.GetResultsByTypeWithPagination(resultType, request.Page, request.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取该类型的扫描结果"})
		return
	}

	// 直接返回结果数组，保持与现有格式一致
	c.JSON(http.StatusOK, results)
}

// UpdateResult 更新指定 ID 的扫描结果
func (h *ResultHandler) UpdateResult(c *gin.Context) {
	id := c.Param("id")
	var updatedData struct {
		Type    string      `json:"type" binding:"required"`
		Payload interface{} `json:"payload" binding:"required"`
	}

	if err := c.ShouldBindJSON(&updatedData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}

	existingResult, err := h.resultService.GetResultByID(id)
	if err != nil {
		if err.Error() == "result not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "未找到该扫描结果"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取扫描结果失败"})
		return
	}

	existingResult.Type = updatedData.Type
	existingResult.Data = updatedData.Payload

	if err := h.resultService.UpdateResult(id, existingResult); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新扫描结果失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "扫描结果更新成功"})
}

// DeleteResult 删除指定 ID 的扫描结果
func (h *ResultHandler) DeleteResult(c *gin.Context) {
	id := c.Param("id")

	if err := h.resultService.DeleteResult(id); err != nil {
		if err.Error() == "result not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "未找到该扫描结果"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除扫描结果失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "扫描结果已删除"})
}

// MarkResultAsRead 根据任务 ID 修改任务的已读状态（支持已读/未读切换）
func (h *ResultHandler) MarkResultAsRead(c *gin.Context) {
	resultID := c.Param("id")

	// 从请求体获取新的 isRead 状态
	var request struct {
		IsRead bool `json:"is_read"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}

	// 调用服务层的 MarkResultAsRead 方法，传入 resultID 和新的 isRead 状态
	if err := h.resultService.MarkResultAsRead(resultID, request.IsRead); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法更新任务的已读状态"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "任务已成功标记为已读/未读"})
}

// MarkEntryAsRead 根据任务 ID 和条目 ID 修改条目的已读状态（支持已读/未读切换）
func (h *ResultHandler) MarkEntryAsRead(c *gin.Context) {
	resultID := c.Param("id")
	entryID := c.Param("entry_id")

	// 从请求体获取 isRead 状态
	var request struct {
		IsRead bool `json:"is_read"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}

	// 调用服务层方法，传入 isRead 状态
	if err := h.resultService.MarkEntryAsRead(resultID, entryID, request.IsRead); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法更新条目的已读状态"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "条目已成功标记为已读/未读"})
}

// ResolveSubdomainIPHandler 处理子域名 IP 解析请求
func (h *ResultHandler) ResolveSubdomainIPHandler(c *gin.Context) {
	resultID := c.Param("id")

	var request struct {
		EntryIDs []string `json:"entryIds" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	result, err := h.dnsService.ResolveSubdomainIPs(resultID, request.EntryIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "解析子域名IP失败",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "解析完成",
		"result":  result,
	})
}

func (h *ResultHandler) ProbeHandler(c *gin.Context) {
	resultID := c.Param("id")

	var request struct {
		EntryIDs []string `json:"entryIds" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 使用通用的 ProbeTargets 方法
	result, err := h.httpxService.ProbeTargets(resultID, request.EntryIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "HTTP探测失败",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "探测完成",
		"result":  result,
	})
}
