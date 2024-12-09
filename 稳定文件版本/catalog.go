package gb28181

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"28181sip/common"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// Device 表示从XML中解析出的单个设备信息。
type Device struct {
	DeviceID     string `xml:"DeviceID"`     // 设备ID
	Name         string `xml:"Name"`         // 设备名称
	Manufacturer string `xml:"Manufacturer"` // 制造商
}

// CatalogResponse 表示XML中的目录响应结构。
type CatalogResponse struct {
	CmdType    string `xml:"CmdType"`  // 命令类型
	SN         int    `xml:"SN"`       // 序列号
	DeviceID   string `xml:"DeviceID"` // 设备ID
	SumNum     int    `xml:"SumNum"`   // 总数
	DeviceList struct {
		Item []Device `xml:"Item"` // 设备列表
	} `xml:"DeviceList"`
}

// KeepaliveNotify 表示XML中的保活通知结构。
type KeepaliveNotify struct {
	CmdType  string `xml:"CmdType"`  // 命令类型
	SN       int    `xml:"SN"`       // 序列号
	DeviceID string `xml:"DeviceID"` // 设备ID
	Status   string `xml:"Status"`   // 状态
	Info     struct {
		DeviceIDs []string `xml:"DeviceID"` // 设备ID列表
	} `xml:"Info"`
}

// SIP相关的响应常量。
const (
	SipUnauthorized = "401 Unauthorized"
	SipNotFound     = "404 Not Found"
	SipOK           = "200 OK"         // SIP成功响应
	Timeout         = 30 * time.Second // 超时时间
	MaxAttempts     = 5                // 最大尝试次数
)

/**
 * @Name handleIncomingMessage
 * @Description 处理传入的UDP消息
 * @param conn UDP连接
 * @return net.UDPAddr, error
 */

func handleIncomingMessage(conn *net.UDPConn) (*net.UDPAddr, error) {
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(Timeout))

	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		common.Errorf("读取消息时发生错误: %v", err)
		return nil, fmt.Errorf("读取消息时发生错误: %v", err)
	}

	message := string(buffer[:n])
	common.Debugf("收到的消息: %s", message)

	switch {
	case strings.Contains(message, "REGISTER sip:"):
		common.Infof("从以下地址接收到SIP REGISTER: %v", remoteAddr)
		c_sendSIPResponse(conn, remoteAddr, message, SipOK)
		return remoteAddr, nil
	case strings.Contains(message, "Keepalive"):
		common.Infof("从以下地址接收到保活消息: %v", remoteAddr)
		handleKeepalive(conn, remoteAddr, message)
		return remoteAddr, nil
	default:
		return nil, fmt.Errorf("收到意外的消息类型")
	}
}

/**
 * @Name handleKeepalive
 * @Description 处理保活通知
 * @param conn UDP连接
 * @param remoteAddr 远程地址
 * @param message 消息内容
 * @return void
 */
func handleKeepalive(conn *net.UDPConn, remoteAddr *net.UDPAddr, message string) {
	var keepalive KeepaliveNotify
	xmlContent := extractXMLContent(message)
	err := parseXML(xmlContent, &keepalive)
	if err != nil {
		common.Errorf("解析保活XML时发生错误: %v", err)
		return
	}

	common.Infof("保活 - 设备ID: %s, 状态: %s", keepalive.DeviceID, keepalive.Status)
	common.Debugf("已连接的设备: %v", keepalive.Info.DeviceIDs)

	c_sendSIPResponse(conn, remoteAddr, message, SipOK)
}

// c_sendSIPResponse 构建并发送SIP响应。
/**
 * @Name c_sendSIPResponse
 * @Description 构建并发送SIP响应
 * @param conn UDP连接
 * @param remoteAddr 远程地址
 * @param originalMessage 原始消息
 * @param statusCode 响应状态码
 * @return void
 */
func c_sendSIPResponse(conn *net.UDPConn, remoteAddr *net.UDPAddr, originalMessage, statusCode string) {
	response := fmt.Sprintf("SIP/2.0 %s\r\n", statusCode) +
		"Via: " + extractHeader(originalMessage, "Via:") + "\r\n" +
		"From: " + extractHeader(originalMessage, "From:") + "\r\n" +
		"To: " + extractHeader(originalMessage, "To:") + "\r\n" +
		"Call-ID: " + extractHeader(originalMessage, "Call-ID:") + "\r\n" +
		"CSeq: " + extractHeader(originalMessage, "CSeq:") + "\r\n" +
		"User-Agent: GoSIP\r\n" +
		"Content-Length: 0\r\n\r\n"

	_, err := conn.WriteToUDP([]byte(response), remoteAddr)
	if err != nil {
		common.Errorf("发送%s响应时发生错误: %v", statusCode, err)
	} else {
		common.Infof("已发送%s响应", statusCode)
	}
}

/**
 * @Name extractHeader
 * @Description 从SIP消息中提取特定的头部
 * @param message SIP消息
 * @param header 头部名称
 * @return string
 */
func extractHeader(message, header string) string {
	lines := strings.Split(message, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, header) {
			return strings.TrimPrefix(line, header+" ")
		}
	}
	return ""
}

/**
 * @Name extractXMLContent
 * @Description 从SIP消息中提取XML内容
 * @param message SIP消息
 * @return string
 */
func extractXMLContent(message string) string {
	parts := strings.Split(message, "\r\n\r\n")
	if len(parts) < 2 {
		return ""
	}

	// 查找XML开始标记
	xmlStart := strings.Index(parts[1], "<?xml")
	if xmlStart == -1 {
		return ""
	}

	return parts[1][xmlStart:]
}

/**
 * @Name sendCatalogQuery
 * @Description 发送目录查询
 * @param conn UDP连接
 * @param serverAddr 服务器地址
 * @return error
 */
func sendCatalogQuery(conn *net.UDPConn, serverAddr *net.UDPAddr) error {
	catalogQuery := "MESSAGE sip:34020000001110000011@6201000000 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 100.100.155.157:5060;rport;branch=z9hG4bK" + fmt.Sprint(time.Now().UnixNano()) + "\r\n" +
		"From: <sip:62010000002000000001@6201000000>;tag=" + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
		"To: <sip:34020000001110000011@6201000000>\r\n" +
		"Call-ID: " + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
		"CSeq: 20 MESSAGE\r\n" +
		"Content-Type: Application/MANSCDP+xml\r\n" +
		"Max-Forwards: 70\r\n" +
		"User-Agent: GoSIP\r\n" +
		"Content-Length: 164\r\n" +
		"\r\n" +
		"<?xml version=\"1.0\" encoding=\"gb2312\"?>\r\n" +
		"<Query>\r\n" +
		"<CmdType>Catalog</CmdType>\r\n" +
		"<SN>1</SN>\r\n" +
		"<DeviceID>34020000001110000011</DeviceID>\r\n" +
		"</Query>"

	for i := 0; i < MaxAttempts; i++ {
		_, err := conn.WriteToUDP([]byte(catalogQuery), serverAddr)
		if err != nil {
			common.Errorf("第%d次发送目录查询失败: %v", i+1, err)
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		common.Infof("第%d次目录查询已发送", i+1)
		return nil
	}
	return fmt.Errorf("发送目录查询失败，已达到最大尝试次数")
}

/**
 * @Name receiveAndParseCatalogResponse
 * @Description 接收并解析目录响应
 * @param conn UDP连接
 * @return error
 */
func receiveAndParseCatalogResponse(conn *net.UDPConn) error {
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		common.Errorf("从UDP读取时发生错误: %v", err)
		return fmt.Errorf("从UDP读取时发生错误: %v", err)
	}

	response := string(buffer[:n])
	common.Debugf("收到的响应: %s", response)

	xmlContent := extractXMLContent(response)
	if xmlContent == "" {
		common.Error("响应中未找到XML内容")
		return fmt.Errorf("响应中未找到XML内容")
	}

	if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
		var catalog CatalogResponse
		err = parseXML(xmlContent, &catalog)
		if err != nil {
			common.Errorf("解析XML时发生错误: %v", err)
			return fmt.Errorf("解析XML时发生错误: %v", err)
		}

		common.Infof("目录响应 - 命令类型: %s, 序列号: %d, 设备ID: %s, 总数: %d",
			catalog.CmdType, catalog.SN, catalog.DeviceID, catalog.SumNum)

		common.Info("发现的设备:")
		for _, device := range catalog.DeviceList.Item {
			common.Infof("设备ID: %s, 名称: %s, 制造商: %s",
				device.DeviceID, device.Name, device.Manufacturer)
		}

	} else if strings.Contains(xmlContent, "<CmdType>Keepalive</CmdType>") {
		var keepalive KeepaliveNotify
		err = parseXML(xmlContent, &keepalive)
		if err != nil {
			common.Errorf("解析保活XML时发生错误: %v", err)
			return fmt.Errorf("解析保活XML时发生错误: %v", err)
		}

		common.Infof("保活 - 设备ID: %s, 状态: %s", keepalive.DeviceID, keepalive.Status)
		common.Info("已连接的设备:")
		for _, deviceID := range keepalive.Info.DeviceIDs {
			common.Infof("设备ID: %s", deviceID)
		}
	} else {
		common.Error("未知的响应类型")
		return fmt.Errorf("未知的响应类型")
	}

	return nil
}

/**
 * @Name parseXML
 * @Description 将XML内容解码到提供的结构体中。
 * @param xmlContent XML内容
 * @param v 解码的目标结构体
 * @return error
 */
func parseXML(xmlContent string, v interface{}) error {
	decoder := xml.NewDecoder(bytes.NewReader([]byte(xmlContent)))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.ToLower(charset) == "gb2312" {
			return transform.NewReader(input, simplifiedchinese.GB18030.NewDecoder()), nil
		}
		return input, nil
	}
	return decoder.Decode(v)
}

/**
 * @Name Getdevice
 * @Description 初始化UDP通信
 * @param t 协议类型
 * @param addr 地址
 */
func Getdevice(t string, addr string) {
	localAddr, err := net.ResolveUDPAddr(t, addr)
	if err != nil {
		common.Errorf("解析本地地址时发生错误: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		common.Errorf("监听5060端口时发生错误: %v", err)
		return
	}
	defer conn.Close()

	common.Info("正在监听5060端口上的传入消息...")

	var nvrAddr *net.UDPAddr
	for nvrAddr == nil {
		nvrAddr, err = handleIncomingMessage(conn)
		if err != nil {
			common.Error(err)
		}
	}

	common.Info("与NVR的通信已经建立。正在发送目录查询...")

	responseChan := make(chan error, 1)

	go func() {
		err := sendCatalogQuery(conn, nvrAddr)
		if err != nil {
			responseChan <- err
			return
		}

		for i := 0; i < MaxAttempts; i++ {
			err = receiveAndParseCatalogResponse(conn)
			if err == nil {
				responseChan <- nil
				return
			}
			common.Errorf("第%d次尝试接收响应: %v", i+1, err)

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				err = sendCatalogQuery(conn, nvrAddr)
				if err != nil {
					continue
				}
			}
			time.Sleep(time.Duration(i+1) * time.Second)
		}
		responseChan <- fmt.Errorf("未能收到有效的目录响应")
	}()

	for { // 禁止程序自动退出
		select {
		case err := <-responseChan:
			if err != nil {
				common.Errorf("目录查询失败: %v", err)
			}
		case <-time.After(60 * time.Second):
			common.Error("目录查询总体超时")
		}
	}

}
