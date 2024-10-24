package gb28181

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

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
	SipOK       = "200 OK"         // SIP成功响应
	Timeout     = 30 * time.Second // 超时时间
	MaxAttempts = 5                // 最大尝试次数
)

// handleIncomingMessage 处理传入的UDP消息。
func handleIncomingMessage(conn *net.UDPConn) (*net.UDPAddr, error) {
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(Timeout)) // 设置读取超时

	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取消息时发生错误: %v", err)
	}

	message := string(buffer[:n])
	fmt.Println("收到的消息:", message)

	switch {
	case strings.Contains(message, "REGISTER sip:"):
		fmt.Println("从以下地址接收到SIP REGISTER:", remoteAddr)
		sendSIPResponse(conn, remoteAddr, message, SipOK)
		return remoteAddr, nil
	case strings.Contains(message, "Keepalive"):
		fmt.Println("从以下地址接收到保活消息:", remoteAddr)
		handleKeepalive(conn, remoteAddr, message)
		return remoteAddr, nil
	default:
		return nil, fmt.Errorf("收到意外的消息类型")
	}
}

// handleKeepalive 处理保活通知。
func handleKeepalive(conn *net.UDPConn, remoteAddr *net.UDPAddr, message string) {
	var keepalive KeepaliveNotify
	xmlContent := extractXMLContent(message)
	err := parseXML(xmlContent, &keepalive)
	if err != nil {
		fmt.Println("解析保活XML时发生错误:", err)
		return
	}

	fmt.Printf("保活 - 设备ID: %s, 状态: %s\n", keepalive.DeviceID, keepalive.Status)
	fmt.Println("已连接的设备:", keepalive.Info.DeviceIDs)

	sendSIPResponse(conn, remoteAddr, message, SipOK)
}

// sendSIPResponse 构建并发送SIP响应。
func sendSIPResponse(conn *net.UDPConn, remoteAddr *net.UDPAddr, originalMessage, statusCode string) {
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
		fmt.Printf("发送%s响应时发生错误: %v\n", statusCode, err)
	} else {
		fmt.Printf("已发送%s响应\n", statusCode)
	}
}

// extractHeader 从SIP消息中提取特定的头部。
func extractHeader(message, header string) string {
	lines := strings.Split(message, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, header) {
			return strings.TrimPrefix(line, header+" ")
		}
	}
	return ""
}

// extractXMLContent 从SIP消息中提取XML内容。
func extractXMLContent(message string) string {
	xmlStart := strings.Index(message, "<?xml")
	if xmlStart == -1 {
		return ""
	}
	return message[xmlStart:]
}

// From: <sip:62010000002000000001@620100000>;tag=%d
// To: <sip:340200000011100000011@620100000>
// sendCatalogQuery 通过UDP发送目录查询。
// func sendCatalogQuery(conn *net.UDPConn, serverAddr *net.UDPAddr) error {
// 	catalogQuery := "MESSAGE sip:34020000001110000011@6201000000 SIP/2.0\r\n" +
// 		"Via: SIP/2.0/UDP 100.100.155.157:5060;rport;branch=z9hG4bK1491613741\r\n" +
// 		"From: <sip:62010000002000000001@6201000000>;tag=387153261\r\n" +
// 		"To: <sip:34020000001110000011@6201000000>\r\n" +
// 		"Call-ID: 200001\r\n" +
// 		"CSeq: 20 MESSAGE\r\n" +
// 		"Content-Type: Application/MANSCDP+xml\r\n" +
// 		"Max-Forwards: 70\r\n" +
// 		"User-Agent: GoSIP\r\n" +
// 		"Content-Length: 164\r\n" +
// 		"\r\n" +
// 		"<?xml version=\"1.0\"?>\r\n" +
// 		"<Query>\r\n" +
// 		"<CmdType>Catalog</CmdType>\r\n" +
// 		"<SN>1</SN>\r\n" +
// 		"<DeviceID>34020000001110000011</DeviceID>\r\n" +
// 		"</Query>"

// 	_, err := conn.WriteToUDP([]byte(catalogQuery), serverAddr)
// 	if err != nil {
// 		return fmt.Errorf("发送目录查询时发生错误: %v", err)
// 	}
// 	fmt.Println("目录查询已发送")
// 	return nil
// }
func sendCatalogQuery(conn *net.UDPConn, serverAddr *net.UDPAddr) error {
    // 修改From和To地址以匹配设备发送的格式
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
        "<?xml version=\"1.0\" encoding=\"gb2312\"?>\r\n" + // 添加gb2312编码
        "<Query>\r\n" +
        "<CmdType>Catalog</CmdType>\r\n" +
        "<SN>1</SN>\r\n" +
        "<DeviceID>34020000001110000011</DeviceID>\r\n" +
        "</Query>"

    // 多次尝试发送
    for i := 0; i < MaxAttempts; i++ {
        _, err := conn.WriteToUDP([]byte(catalogQuery), serverAddr)
        if err != nil {
            fmt.Printf("第%d次发送目录查询失败: %v\n", i+1, err)
            time.Sleep(time.Second * time.Duration(i+1))
            continue
        }
        fmt.Printf("第%d次目录查询已发送\n", i+1)
        return nil
    }
    return fmt.Errorf("发送目录查询失败，已达到最大尝试次数")
}

// receiveAndParseCatalogResponse 接收并解析目录响应。
func receiveAndParseCatalogResponse(conn *net.UDPConn) error {
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) // 设置读取超时

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return fmt.Errorf("从UDP读取时发生错误: %v", err)
	}

	response := string(buffer[:n])
	fmt.Println("收到的响应:", response)

	xmlContent := extractXMLContent(response)
	if xmlContent == "" {
		return fmt.Errorf("响应中未找到XML内容")
	}

	// Identify if it's a Keepalive or Catalog response based on the CmdType
	if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
		var catalog CatalogResponse
		err = parseXML(xmlContent, &catalog)
		if err != nil {
			return fmt.Errorf("解析XML时发生错误: %v", err)
		}

		fmt.Printf("目录响应 - 命令类型: %s, 序列号: %d, 设备ID: %s, 总数: %d\n",
			catalog.CmdType, catalog.SN, catalog.DeviceID, catalog.SumNum)

		fmt.Println("发现的设备:")
		for _, device := range catalog.DeviceList.Item {
			fmt.Printf("设备ID: %s, 名称: %s, 制造商: %s\n", device.DeviceID, device.Name, device.Manufacturer)
		}

	} else if strings.Contains(xmlContent, "<CmdType>Keepalive</CmdType>") {
		var keepalive KeepaliveNotify
		err = parseXML(xmlContent, &keepalive)
		if err != nil {
			return fmt.Errorf("解析保活XML时发生错误: %v", err)
		}

		fmt.Printf("保活 - 设备ID: %s, 状态: %s\n", keepalive.DeviceID, keepalive.Status)
		fmt.Println("已连接的设备:")
		for _, deviceID := range keepalive.Info.DeviceIDs {
			fmt.Printf("设备ID: %s\n", deviceID)
		}
	} else {
		return fmt.Errorf("未知的响应类型")
	}

	return nil
}

// parseXML 将XML内容解码到提供的结构体中。
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

// getdevice list  函数初始化UDP通信。
func Getdevice(t string,addr string) {
	// localAddr, err := net.ResolveUDPAddr("udp", "100.100.155.157:5060") // 解析本地地址
	localAddr, err := net.ResolveUDPAddr(t, addr) // 解析本地地址ååå
	if err != nil {
		fmt.Println("解析本地地址时发生错误:", err)
		return
	}

	conn, err := net.ListenUDP("udp", localAddr) // 监听UDP端口
	if err != nil {
		fmt.Println("监听5060端口时发生错误:", err)
		return
	}
	defer conn.Close()

	fmt.Println("正在监听5060端口上的传入消息...")

	var nvrAddr *net.UDPAddr
	for nvrAddr == nil {
		nvrAddr, err = handleIncomingMessage(conn)
		if err != nil {
			fmt.Println(err)
		}
	}

	fmt.Println("与NVR的通信已经建立。正在发送目录查询...")
 // 创建一个通道用于接收响应
 responseChan := make(chan error, 1)

 // 在goroutine中发送查询并等待响应
 go func() {
	 err := sendCatalogQuery(conn, nvrAddr)
	 if err != nil {
		 responseChan <- err
		 return
	 }

	 // 等待并解析响应
	 for i := 0; i < MaxAttempts; i++ {
		 err = receiveAndParseCatalogResponse(conn)
		 if err == nil {
			 responseChan <- nil
			 return
		 }
		 fmt.Printf("第%d次尝试接收响应: %v\n", i+1, err)
		 
		 // 如果是超时错误，重新发送查询
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

 // 设置总体超时
 select {
 case err := <-responseChan:
	 if err != nil {
		 fmt.Println("目录查询失败:", err)
	 }
 case <-time.After(60 * time.Second):
	 fmt.Println("目录查询总体超时")
 }
}

// func receiveAndParseCatalogResponse(conn *net.UDPConn) error {
// 	buffer := make([]byte, 4096)
// 	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) // 设置读取超时

// 	n, _, err := conn.ReadFromUDP(buffer)
// 	if err != nil {
// 		return fmt.Errorf("从UDP读取时发生错误: %v", err)
// 	}

// 	response := string(buffer[:n])
// 	fmt.Println("收到的响应:", response)

// 	xmlContent := extractXMLContent(response)
// 	if xmlContent == "" {
// 		return fmt.Errorf("响应中未找到XML内容")
// 	}

// 	var catalog CatalogResponse
// 	err = parseXML(xmlContent, &catalog)
// 	if err != nil {
// 		return fmt.Errorf("解析XML时发生错误: %v", err)
// 	}

// 	fmt.Printf("目录响应 - 命令类型: %s, 序列号: %d, 设备ID: %s, 总数: %d\n",
// 		catalog.CmdType, catalog.SN, catalog.DeviceID, catalog.SumNum)

// 	fmt.Println("发现的设备:")
// 	for _, device := range catalog.DeviceList.Item {
// 		fmt.Printf("设备ID: %s, 名称: %s, 制造商: %s\n", device.DeviceID, device.Name, device.Manufacturer)
// 	}

//		return nil
//	}