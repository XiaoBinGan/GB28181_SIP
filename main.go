package main

import (
	"28181sip/common"
	"28181sip/gb28181"
)

func main() {
	common.Info("Starting application...")
	/**
	 * 1.对接下级设备获取设备列表
	 */
	// gb28181.Getdevice("udp", "100.100.155.157:5060")
	/**
	 * 2.对接上级平台级设备获取设备列表
	 */
	gb28181.SimulateNVR("conf/config.yaml")
	/**
	 * 3.对接上级平台级请求
	 */
	// buffer := make([]byte, 4096)
	// conn := gb28181.Conn
	// for {
	// 	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	// 	if err != nil {
	// 		common.Errorf("接收消息时出错: %v", err)
	// 		return
	// 	}
	// 	message := string(buffer[:n])
	// 	message = gb28181.CleanSIPMessage(message) // 添加这行
	// 	err = gb28181.HandleSIPRequest(conn, message, remoteAddr)
	// 	if err != nil {
	// 		common.Errorf("处理SIP请求时出错: %v", err)
	// 	}
	// }
}
