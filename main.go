package main

import (
	"28181sip/common"
	"28181sip/gb28181"
	"28181sip/handler"
	"28181sip/middleware"
	"fmt"

	_ "28181sip/docs" // 导入 swagger docs

	"github.com/gin-gonic/gin"

	swaggerFiles "github.com/swaggo/files"

	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title task API
// @version 1.0
// @description none
// @host localhost:8080
// @BasePath /api
func main() {
	// 使用common包中的Info函数输出启动信息
	common.Info("Starting application... Server")
	/**
	 * 1.对接下级设备获取设备列表
	 */
	// 调用gb28181包中的Getdevice函数，传入配置文件路径"conf/sipclient.yaml"来获取设备列表
	go func() {
		fmt.Println("Getdevice start")
		gb28181.Getdevice("conf/sipclient.yaml")
		fmt.Println("Getdevice end")
	}()

	/**
	 * 2.对接上级平台级设备推送设备列表
	 */
	// 调用gb28181包中的SimulateNVR函数，传入配置文件路径"conf/config.yaml"来模拟NVR设备并推送设备列表
	// gb28181.SimulateNVR("conf/config.yaml")

	/**
	* 3.接收跨网闸的请求
	 */
	// 创建一个默认的gin引擎实例
	r := gin.Default()
	// 使用UnifiedResponseMiddleware中间件来统一响应格式
	r.Use(middleware.UnifiedResponseMiddleware())

	// 创建一个API版本1的路由组
	v1 := r.Group("/api/")
	{
		// 在API版本1的路由组下创建一个任务跟踪的路由组
		task := v1.Group("/task/track")
		{
			// 在任务跟踪的路由组下添加一个POST路由，处理根路径的请求，调用handler.GetTrack函数
			task.POST("", handler.GetTrackHandler)
		}
	}
	// Swagger 文档路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.Run(":8080")
}
