package gb28181

import (
	"28181sip/common"
	"crypto/md5"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// 添加消息计数和去重
var (
	messageCache      sync.Map
	messageExpiration = 5 * time.Second
)

// 清理SIP消息，移除重复内容
func CleanSIPMessage(message string) string {
	// 分离消息头和消息体
	parts := strings.Split(message, "\r\n\r\n")
	if len(parts) < 2 {
		return message
	}

	// 获取唯一的消息头行
	headerLines := strings.Split(parts[0], "\r\n")
	uniqueHeaders := make(map[string]string)

	for _, line := range headerLines {
		if line == "" {
			continue
		}
		// 对于首行（请求行）直接保留
		if !strings.Contains(line, ":") {
			uniqueHeaders["REQUEST_LINE"] = line
			continue
		}

		// 提取header名称
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			headerName := strings.TrimSpace(headerParts[0])
			headerValue := strings.TrimSpace(headerParts[1])
			uniqueHeaders[headerName] = headerValue
		}
	}

	// 重建消息头
	var cleanedMessage strings.Builder
	if requestLine, ok := uniqueHeaders["REQUEST_LINE"]; ok {
		cleanedMessage.WriteString(requestLine + "\r\n")
		delete(uniqueHeaders, "REQUEST_LINE")
	}

	for header, value := range uniqueHeaders {
		cleanedMessage.WriteString(fmt.Sprintf("%s: %s\r\n", header, value))
	}

	// 添加消息体
	cleanedMessage.WriteString("\r\n")
	if len(parts) > 1 {
		// 只保留一个消息体
		cleanedMessage.WriteString(parts[1])
	}

	return cleanedMessage.String()
}

// 清理过期消息缓存
func cleanExpiredMessages() {
	messageCache.Range(func(key, value interface{}) bool {
		if time.Since(value.(time.Time)) > messageExpiration {
			messageCache.Delete(key)
		}
		return true
	})
}

// HandleSIPRequest 处理不同的SIP请求
func HandleSIPRequest(conn *net.UDPConn, message string, remoteAddr *net.UDPAddr) error {
	// 消息去重处理
	messageHash := fmt.Sprintf("%x", md5.Sum([]byte(message)))
	if _, exists := messageCache.Load(messageHash); exists {
		common.Info("重复消息，忽略处理")
		return nil
	}
	messageCache.Store(messageHash, time.Now())

	// 首先确保消息完整性
	if !strings.Contains(message, "\r\n\r\n") {
		common.Error("接收到不完整的SIP消息")
		return fmt.Errorf("incomplete SIP message")
	}

	common.Infof("收到原始消息:\n%s", message)

	// 提取关键SIP头部
	callID := extractHeader(message, "Call-ID:")
	from := extractHeader(message, "From:")
	to := extractHeader(message, "To:")
	via := extractHeader(message, "Via:")
	cseq := extractHeader(message, "CSeq:")

	if strings.Contains(message, "MESSAGE sip:") {
		xmlContent := extractXMLContent(message)
		if xmlContent != "" {
			common.Infof("提取的XML内容:\n%s", xmlContent)

			if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
				response := fmt.Sprintf(
					"SIP/2.0 200 OK\r\n"+
						"Via: %s\r\n"+
						"From: %s\r\n"+
						"To: %s\r\n"+
						"Call-ID: %s\r\n"+
						"CSeq: %s\r\n"+
						"Content-Type: Application/MANSCDP+xml\r\n"+
						"Content-Length: %d\r\n"+
						"\r\n"+
						"%s",
					via, from, to, callID, cseq,
					len(generateCatalogResponse()),
					generateCatalogResponse())

				common.Infof("发送目录响应:\n%s", response)

				// 多次尝试发送响应
				for i := 0; i < 3; i++ {
					_, err := conn.WriteToUDP([]byte(response), remoteAddr)
					if err == nil {
						break
					}
					if i == 2 {
						common.Errorf("发送响应失败: %v", err)
						return err
					}
					time.Sleep(100 * time.Millisecond)
				}
				return nil
			}
		}
	}

	// 对于其他类型的请求返回200 OK
	response := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Via: %s\r\n"+
			"From: %s\r\n"+
			"To: %s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %s\r\n"+
			"Content-Length: 0\r\n"+
			"\r\n",
		via, from, to, callID, cseq)

	_, err := conn.WriteToUDP([]byte(response), remoteAddr)
	return err
	// // 首先清理消息
	// cleanedMessage := CleanSIPMessage(message)
	// common.Infof("收到清理后的消息:\n%s", cleanedMessage)

	// // 解析请求类型
	// if strings.Contains(message, "REGISTER sip:") {
	// 	common.Infof("收到来自 %v 的REGISTER请求", remoteAddr)
	// 	return HandleRegister(conn, message, remoteAddr)
	// } else if strings.Contains(cleanedMessage, "MESSAGE sip:") {
	// 	xmlContent := extractXMLContent(cleanedMessage)
	// 	if xmlContent != "" {
	// 		common.Infof("提取的XML内容:\n%s", xmlContent)

	// 		// 检查是否是目录查询
	// 		if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
	// 			common.Infof("收到目录查询请求")
	// 			return HandleCatalogQuery(conn, remoteAddr, xmlContent)
	// 		}
	// 	}
	// } else if strings.Contains(message, "NOTIFY sip:") {
	// 	common.Infof("收到来自 %v 的NOTIFY请求", remoteAddr)
	// 	return HandleNotify(conn, message, remoteAddr)
	// } else {
	// 	common.Warnf("收到未知类型的SIP请求: %s", message)
	// 	return SendSIPResponse(conn, remoteAddr, message, SipNotFound)
	// }
	// return HandleMessage(conn, cleanedMessage, remoteAddr)
}

// HandleRegister 处理REGISTER请求
func HandleRegister(conn *net.UDPConn, message string, remoteAddr *net.UDPAddr) error {
	// 在这里添加注册请求的验证逻辑
	// 例如，您可以检查授权头，或执行其他身份验证逻辑

	// 假设注册成功，发送200 OK响应
	return SendSIPResponse(conn, remoteAddr, message, SipOK)
}

// HandleMessage 处理MESSAGE请求
func handleMessage(conn *net.UDPConn, message string, remoteAddr *net.UDPAddr) error {
	// 检查MESSAGE请求的内容，通常会包含XML数据（如目录查询或保活）
	xmlContent := extractXMLContent(message)
	if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
		common.Infof("收到目录查询请求")
		return HandleCatalogQuery(conn, remoteAddr, xmlContent)
	} else if strings.Contains(xmlContent, "<CmdType>Keepalive</CmdType>") {
		common.Infof("收到保活消息")
		return HandleKeepaliveNotify(conn, remoteAddr, xmlContent)
	} else {
		common.Warnf("未知的MESSAGE请求类型")
		return SendSIPResponse(conn, remoteAddr, message, SipNotFound)
	}
}

// HandleNotify 处理NOTIFY请求
func HandleNotify(conn *net.UDPConn, message string, remoteAddr *net.UDPAddr) error {
	// 解析NOTIFY请求中的XML数据并执行相应操作
	common.Infof("处理NOTIFY请求，消息: %s", message)
	return SendSIPResponse(conn, remoteAddr, message, SipOK)
}

// HandleCatalogQuery 处理目录查询请求
//
//	func HandleCatalogQuery(conn *net.UDPConn, remoteAddr *net.UDPAddr, xmlContent string) error {
//		// 解析目录查询XML内容并返回目录信息
//		catalogResponse := generateCatalogResponse()
//		return sendSIPResponseWithContent(conn, remoteAddr, SipOK, catalogResponse)
//	}
func HandleCatalogQuery(conn *net.UDPConn, remoteAddr *net.UDPAddr, xmlContent string) error {
	common.Infof("正在处理目录查询请求")

	// 生成目录响应
	response := generateCatalogResponse()

	// 构建完整的SIP响应消息
	sipResponse := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Content-Type: Application/MANSCDP+xml\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		len(response),
		response,
	)

	common.Infof("发送目录响应:\n%s", sipResponse)

	_, err := conn.WriteToUDP([]byte(sipResponse), remoteAddr)
	if err != nil {
		common.Errorf("发送目录响应失败: %v", err)
		return err
	}

	return nil
}

// HandleKeepaliveNotify 处理保活通知请求
func HandleKeepaliveNotify(conn *net.UDPConn, remoteAddr *net.UDPAddr, xmlContent string) error {
	// 解析保活通知XML内容
	var keepalive KeepaliveNotify
	err := parseXML(xmlContent, &keepalive)
	if err != nil {
		common.Errorf("解析保活通知XML时出错: %v", err)
		return err
	}
	common.Infof("保活 - 设备ID: %s, 状态: %s", keepalive.DeviceID, keepalive.Status)
	return SendSIPResponse(conn, remoteAddr, "", SipOK)
}

// SendSIPResponse 发送SIP响应
func SendSIPResponse(conn *net.UDPConn, remoteAddr *net.UDPAddr, originalMessage, statusCode string) error {
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
	}
	return err
}

// sendSIPResponseWithContent 发送带有内容的SIP响应
func sendSIPResponseWithContent(conn *net.UDPConn, remoteAddr *net.UDPAddr, statusCode, content string) error {
	response := fmt.Sprintf("SIP/2.0 %s\r\n", statusCode) +
		"Content-Type: Application/MANSCDP+xml\r\n" +
		"User-Agent: GoSIP\r\n" +
		"Content-Length: %d\r\n\r\n%s"

	response = fmt.Sprintf(response, len(content), content)
	_, err := conn.WriteToUDP([]byte(response), remoteAddr)
	if err != nil {
		common.Errorf("发送响应时出错: %v", err)
	}
	return err
}

// generateCatalogResponse 生成一个目录响应的示例
//
//	func generateCatalogResponse() string {
//		common.Infof("生成响应的格式")
//		return "<?xml version=\"1.0\" encoding=\"gb2312\"?>\r\n" +
//			"<Response>\r\n" +
//			"<CmdType>Catalog</CmdType>\r\n" +
//			"<SN>1</SN>\r\n" +
//			"<DeviceID>34020000001110000011</DeviceID>\r\n" +
//			"<SumNum>1</SumNum>\r\n" +
//			"<DeviceList>\r\n" +
//			"<Item>\r\n" +
//			"<DeviceID>34020000001110000011</DeviceID>\r\n" +
//			"<Name>Sample Device</Name>\r\n" +
//			"<Manufacturer>Sample Manufacturer</Manufacturer>\r\n" +
//			"</Item>\r\n" +
//			"</DeviceList>\r\n" +
//			"</Response>"
//	}
func generateCatalogResponse() string {
	return `<?xml version="1.0" encoding="GB2312"?>
<Response>
    <CmdType>Catalog</CmdType>
    <SN>1</SN>
    <DeviceID>34020000001110000011</DeviceID>
    <SumNum>1</SumNum>
    <DeviceList>
        <Item>
            <DeviceID>34020000001110000011</DeviceID>
            <Name>IPC</Name>
            <Manufacturer>Manufacturer</Manufacturer>
            <Model>Model</Model>
            <Owner>Owner</Owner>
            <CivilCode>CivilCode</CivilCode>
            <Address>Address</Address>
            <Parental>0</Parental>
            <SafetyWay>0</SafetyWay>
            <RegisterWay>1</RegisterWay>
            <Secrecy>0</Secrecy>
            <Status>ON</Status>
        </Item>
    </DeviceList>
</Response>`
}

// 为了接收和处理各种SIP信令请求，我们可以创建一个单独的文件 sip_handler.go，用于专门处理来自其他平台的SIP消息（如REGISTER、MESSAGE、NOTIFY等）。这个文件将包含函数来解析不同类型的SIP请求并执行相应的操作。

// 以下是 sip_handler.go 的示例代码：
// 代码说明

// 	1.	handleSIPRequest: 该函数会根据消息内容判断SIP请求的类型（REGISTER、MESSAGE、NOTIFY）并调用相应的处理函数。
// 	2.	handleRegister: 处理REGISTER请求的函数。可以在此添加注册验证逻辑，此处假设注册成功，直接返回 200 OK。
// 	3.	handleMessage: 处理MESSAGE请求。根据消息内容解析出XML数据，并判断是目录查询还是保活通知，然后调用对应的处理函数。
// 	4.	handleCatalogQuery: 处理目录查询请求。调用generateCatalogResponse生成目录响应的XML内容，并发送回去。
// 	5.	handleKeepaliveNotify: 处理保活通知请求，解析保活XML数据并记录相关状态。
// 	6.	sendSIPResponse: 发送不带内容的基本SIP响应。
// 	7.	sendSIPResponseWithContent: 发送带有内容（如XML）的SIP响应，用于目录响应等场景。
// 	8.	generateCatalogResponse: 一个生成目录查询响应XML的示例函数，用于返回模拟的设备信息列表。

// 使用示例

// 在接收到SIP请求时，可以调用 handleSIPRequest 进行处理，例如在主程序中：

// 接收SIP消息并调用处理函数
// buffer := make([]byte, 4096)
// n, remoteAddr, err := conn.ReadFromUDP(buffer)
// if err != nil {
//     common.Errorf("接收消息时出错: %v", err)
//     return
// }
// message := string(buffer[:n])
// err = handleSIPRequest(conn, message, remoteAddr)
// if err != nil {
//     common.Errorf("处理SIP请求时出错: %v", err)
// }

// 这样，将所有的SIP信令处理逻辑独立到 sip_handler.go 文件中，使代码更加模块化和清晰。
