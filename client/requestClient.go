package client
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// 定义请求结构体
type RequestBody struct {
	Image     string `json:"image"`
	TrackInfo string `json:"trackInfo"`
}

// 封装发送POST请求的函数
/**
 * @Description: 发送POST请求
 * @param url 请求地址
 * @param image 图片信息
 * @param trackInfo 跟踪信息
 * @return string 响应内容
 * @return error 错误信息
 */
func SendPostRequest(url, image, trackInfo string) (string, error) {
	// 构造请求体
	requestBody := RequestBody{
		Image:     image,      // 请求体中的图片信息
		TrackInfo: trackInfo,  // 请求体中的跟踪信息
	}

	// 将结构体转换为JSON格式
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %v", err) // 如果转换失败，返回错误信息
	}

	// 发送POST请求
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("error sending POST request: %v", err) // 如果发送请求失败，返回错误信息
	}
	defer resp.Body.Close() // 确保响应体在函数返回前关闭

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err) // 如果读取响应体失败，返回错误信息
	}

	// 返回响应内容
	return string(body), nil // 将响应体转换为字符串并返回
}