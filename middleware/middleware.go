package middleware

import (
	"28181sip/common"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResponseData struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// ErrorResponse是一个辅助函数，用于创建错误响应
// 它接收一个 gin.Context 对象，一个 HTTP 状态码和一个错误消息。
func ErrorResponse(c *gin.Context, code int, message string) {
	// 使用 gin.Context 的 JSON 方法返回一个 JSON 响应。
	// 参数 code 是 HTTP 状态码，例如 400, 500 等。
	// 参数 ResponseData 是一个结构体，包含错误码、错误消息和数据字段。
	// 这里将 Code 设置为传入的 code，Message 设置为传入的 message，Data 设置为 nil。
	common.Error(message)
	c.JSON(code, ResponseData{
		Code:    code,    // 错误码，与传入的 code 相同
		Message: message, // 错误消息，与传入的 message 相同
		Data:    nil,     // 数据字段，这里设置为 nil，表示没有数据
	})
}

// SuccessResponse是一个辅助函数，用于创建成功响应
// 参数 c 是一个 *gin.Context 类型的指针，用于处理 HTTP 请求和响应
// 参数 code 是一个整数，表示 HTTP 响应的状态码
// 参数 data 是一个空接口，表示响应的数据部分，可以是任意类型
func SuccessResponse(c *gin.Context, code int, data interface{}) {
	// 使用 gin 的 JSON 方法将响应数据以 JSON 格式返回给客户端
	// 第一个参数 code 是 HTTP 响应的状态码
	// 第二个参数是一个 ResponseData 结构体实例，包含响应的具体内容
	common.Info("状态 200 success :", data)
	c.JSON(code, ResponseData{
		// Code 字段设置为传入的 code 参数，表示响应的状态码
		Code: code,
		// Message 字段设置为 "成功"，表示响应的消息
		Message: "成功",
		Data:    data,
	})
}

// UnifiedResponseMiddleware是处理统一HTTP响应格式的中间件
func UnifiedResponseMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 调用 c.Next() 继续处理后续的中间件或处理器
		c.Next()

		// 检查是否在处理请求时发生了错误
		if len(c.Errors) > 0 {
			// 获取最后一个错误
			err := c.Errors.Last()
			// 调用 ErrorResponse 函数返回错误响应
			ErrorResponse(c, http.StatusInternalServerError, err.Error())
			// 终止后续处理
			return
		}

		// 检查是否设置了响应状态码
		if c.Writer.Status() == 0 {
			// 如果没有设置状态码，则默认设置为 200 OK
			c.Writer.WriteHeader(http.StatusOK)
		}

		// 如果没有错误，则格式化响应
		if c.Writer.Status() >= http.StatusOK && c.Writer.Status() < http.StatusMultipleChoices {
			// 从上下文中获取响应数据
			data, exists := c.Get("response_data")
			if exists {
				SuccessResponse(c, c.Writer.Status(), data)
				return
			}
		}
	}
}
