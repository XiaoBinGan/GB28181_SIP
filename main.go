package main

import (
	"28181sip/common"
	"28181sip/gb28181"
)

func main() {
	common.Info("Starting application... Server")
	/**
	 * 1.对接下级设备获取设备列表
	 */
	// gb28181.Getdevice("conf/sipclient.yaml")

	/**
	 * 2.对接上级平台级设备推送设备列表
	 */
	gb28181.SimulateNVR("conf/config.yaml")

}
