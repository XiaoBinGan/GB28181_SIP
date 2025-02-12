package handler

import (
	"28181sip/common"
	"28181sip/gb28181"
	"28181sip/models"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// @Summary 获取用户轨迹
// @Description 获取指定用户的轨迹信息
// @Accept json
// @Produce json
// @Param user body models.GetTrackRequest true "用户轨迹请求"
// @Success 200 {object} models.GetTrackRequest
// @Router /task/track [post]
func GetTrackHandler(c *gin.Context) {
	// 定义一个变量req，用于存储从请求中解析出的GetTrackRequest结构体
	var req models.GetTrackRequest
	fmt.Println("GetTrack", c.Request)
	// 尝试从请求的JSON数据中解析出GetTrackRequest结构体，如果解析失败，则返回400错误
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Printf("GetTrack: %v\n", req.Image)
	fmt.Printf("GetTrack: %v\n", req.TrackInfo)
	/****发送大图片时使用**************************************************************************************************************************************************************************************/
	err := gb28181.SendImageInfoInChunks(gb28181.Conn, gb28181.NvrAddr, gb28181.Config_client, req.TrackInfo, req.Image, 1024*1) // 8KB per chunk
	if err != nil {
		common.Errorf("发送图片信息失败: %v", err)
	}
	/******************************************************************************************************************************************************************************************/
	// fmt.Println("req:%#v", &req)
	// 假设data是要返回给客户端的数据
	data := map[string]string{"message": "ok"}

	// 设置"response_data"键的值
	c.Set("response_data", data)

	// 继续处理请求，中间件将在这之后格式化响应
	c.Next()
}
