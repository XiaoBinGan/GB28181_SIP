package gb28181

import (
	"28181sip/common"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"gopkg.in/yaml.v2"
)

// 查询状态结构体
type QueryState struct {
	// sync.Mutex         //加锁确保数线程安全
	FirstStageComplete bool
	DeviceList         []Device
	TotalDevices       int
}

// Device 表示从XML中解析出的单个设备信息。
type Device struct {
	// DeviceID     string `xml:"DeviceID"`     // 设备ID
	// Name         string `xml:"Name"`         // 设备名称
	// Status string `xml:"Status"` // 连接状态
	DeviceID  string `xml:"DeviceID"`  //设备ID
	Name      string `xml:"Name"`      //设备名称
	Status    string `xml:"Status"`    //设备状态
	Longitude string `xml:"Longitude"` //经度
	Latitude  string `xml:"Latitude"`  //纬度
	Address   string `xml:"Address"`   //地址
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

// 引入配置管理
type ClientConfig struct {
	LocalId           string `yaml:"local_id"`
	LocalIP           string `yaml:"local_ip"`
	LocalPort         string `yaml:"local_port"`
	DeviceID          string `yaml:"device_id"`
	DeviceIP          string `yaml:"device_ip"`
	DevicePort        string `yaml:"device_port"`
	DomainID          string `yaml:"domain_id"`
	Password          string `yaml:"password"`
	KeepaliveInterval int    `yaml:"keepalive_interval"`
}

// 确保 QueryState 在整个查询过程中只初始化一次，并在流程中持久化。
func NewQueryState() *QueryState {
	return &QueryState{
		FirstStageComplete: false,
		DeviceList:         []Device{},
		TotalDevices:       0,
	}
}

// MD5哈希辅助函数
func md5Hash(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

/**
 *@Name LoadClientConfig 从YAML文件加载配置
 *@param path url
 *@return ClientConfig,error
 */
func LoadClientConfig(path string) (*ClientConfig, error) {
	config := &ClientConfig{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}
	return config, nil
}

/**
 * @Name ParseWWWAuthenticate
 * @Description 解析WWW-Authenticate头
 * @param message 消息内容
 * @return map[string]string
 */
func ParseWWWAuthenticate(message string) map[string]string {
	authHeader := extractHeader(message, "WWW-Authenticate:")
	if authHeader == "" {
		common.Warnf("未找到WWW-Authenticate头")
		return nil
	}

	common.Debugf("原始WWW-Authenticate头: %s", authHeader)

	authParams := make(map[string]string)
	re := regexp.MustCompile(`(\w+)=["']?([^"',]+)["']?`)
	matches := re.FindAllStringSubmatch(authHeader, -1)

	for _, match := range matches {
		if len(match) == 3 {
			authParams[match[1]] = match[2]
			common.Debugf("解析的认证参数: %s = %s", match[1], match[2])
		}
	}

	return authParams
}

/**
 * @Name CalculateDigestResponse
 * @Description 计算摘要认证响应 (Digest Authentication Response)，用于生成基于摘要认证的响应值。
 * 摘要认证是一种用于 HTTP 协议的安全认证机制，主要用于验证用户身份。
 * 该函数通过用户名、域、密码、HTTP 方法、URI 和服务器发送的 nonce 值计算认证响应。
 * @param username 用户名
 * @param realm 域名 (服务器认证域，用于区分不同服务的认证请求)
 * @param password 用户密码
 * @param method HTTP 方法，如 GET 或 POST
 * @param uri 请求的资源路径
 * @param nonce 服务器发送的随机字符串，用于防止重放攻击
 * @return string 生成的摘要认证响应值
 */
func CalculateDigestResponse(username, realm, password, method, uri, nonce string) string {
	common.Debugf("摘要认证参数: username=%s, realm=%s, method=%s, uri=%s, nonce=%s",
		username, realm, method, uri, nonce)

	ha1 := md5Hash(fmt.Sprintf("%s:%s:%s", username, realm, password))
	ha2 := md5Hash(fmt.Sprintf("%s:%s", method, uri))
	response := md5Hash(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))

	common.Debugf("计算的响应: %s", response)
	return response
}

/**
 * @Name BuildAuthenticatedRegister
 * @Description 构建带认证的 REGISTER 消息，用于向 SIP 服务器进行注册。
 * 本函数通过提取原始 SIP 消息中的关键字段，并结合摘要认证机制，生成认证后的 REGISTER 请求。
 *
 * @param config 客户端配置参数，包含设备ID、密码、域名、IP地址、端口等信息
 * @param originalMessage 原始的 SIP 消息内容，用于提取必要的头信息
 * @param authParams 包含认证相关参数，如 realm 和 nonce
 * @return string 构建的完整 SIP REGISTER 消息内容
 */
func BuildAuthenticatedRegister(config *ClientConfig, originalMessage string, authParams map[string]string) string {
	// 提取原始消息中的关键信息
	fromHeader := extractHeader(originalMessage, "From:")
	toHeader := extractHeader(originalMessage, "To:")
	callID := extractHeader(originalMessage, "Call-ID:")
	viaHeader := extractHeader(originalMessage, "Via:")

	// 从认证参数中获取必要信息
	realm := authParams["realm"]
	nonce := authParams["nonce"]

	// 配置认证参数
	username := config.DeviceID
	password := config.Password // 假设在ClientConfig中新增了Password字段
	method := "REGISTER"
	uri := fmt.Sprintf("sip:%s@%s", config.DeviceID, config.DomainID)

	// 计算摘要响应
	response := CalculateDigestResponse(username, realm, password, method, uri, nonce)

	// 构建认证头
	authHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response)

	registeredMessage := fmt.Sprintf(
		"REGISTER sip:%s@%s SIP/2.0\r\n"+
			"Via: %s\r\n"+
			"From: %s\r\n"+
			"To: %s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: 2 REGISTER\r\n"+
			"Authorization: %s\r\n"+
			"Contact: <sip:%s@%s:%s>\r\n"+
			"Max-Forwards: 70\r\n"+
			"User-Agent: GoSIP\r\n"+
			"Expires: 3600\r\n"+
			"Content-Length: 0\r\n\r\n",
		config.DeviceID, config.DomainID,
		viaHeader,
		fromHeader,
		toHeader,
		callID,
		authHeader,
		config.DeviceID, config.LocalIP, config.LocalPort,
	)

	return registeredMessage
}

/**
 * @Name HandleIncomingMessage
 * @Description 处理传入的UDP消息
 * @param conn UDP连接
 * @return net.UDPAddr, error
 */
func HandleIncomingMessage(conn *net.UDPConn, config *ClientConfig) (*net.UDPAddr, error) {
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
	case strings.Contains(message, "401 Unauthorized"):
		common.Infof("收到401 Unauthorized，需要认证")
		authParams := ParseWWWAuthenticate(message)
		if authParams != nil {
			// 构建带认证的REGISTER请求
			authenticatedRegister := BuildAuthenticatedRegister(config, message, authParams)
			_, err := conn.WriteToUDP([]byte(authenticatedRegister), remoteAddr)
			if err != nil {
				common.Errorf("发送认证请求失败: %v", err)
			}
		}
		return remoteAddr, nil

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
func sendCatalogQuery(conn *net.UDPConn, serverAddr *net.UDPAddr, config *ClientConfig, state *QueryState) error {
	var catalogQuery string
	var sn int

	if !state.FirstStageComplete {
		// 第一阶段查询：获取设备总数
		sn = 1
		catalogQuery = fmt.Sprintf(
			"MESSAGE sip:%s@%s SIP/2.0\r\n"+
				"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
				"From: <sip:%s@%s>;tag=%d\r\n"+
				"To: <sip:%s@%s>\r\n"+
				"Call-ID: %d\r\n"+
				"CSeq: 20 MESSAGE\r\n"+
				"Content-Type: Application/MANSCDP+xml\r\n"+
				"Max-Forwards: 70\r\n"+
				"User-Agent: GoSIP\r\n"+
				"Content-Length: 164\r\n\r\n"+
				"<?xml version=\"1.0\" encoding=\"gb2312\"?>\r\n"+
				"<Query>\r\n"+
				"<CmdType>Catalog</CmdType>\r\n"+
				"<SN>%d</SN>\r\n"+
				"<DeviceID>%s</DeviceID>\r\n"+
				"</Query>",
			config.DeviceID, config.DomainID,
			config.LocalIP, config.LocalPort, time.Now().UnixNano(),
			config.DeviceID, config.DomainID, time.Now().UnixNano()%1000000000,
			config.DeviceID, config.DomainID,
			time.Now().UnixNano()%1000000000,
			sn,
			config.DeviceID,
		)
	} else {
		// 第二阶段查询：分页获取设备详情
		sn = 2
		catalogQuery = fmt.Sprintf(
			"MESSAGE sip:%s@%s SIP/2.0\r\n"+
				"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
				"From: <sip:%s@%s>;tag=%d\r\n"+
				"To: <sip:%s@%s>\r\n"+
				"Call-ID: %d\r\n"+
				"CSeq: 20 MESSAGE\r\n"+
				"Content-Type: Application/MANSCDP+xml\r\n"+
				"Max-Forwards: 70\r\n"+
				"User-Agent: GoSIP\r\n"+
				"Content-Length: 164\r\n\r\n"+
				"<?xml version=\"1.0\" encoding=\"gb2312\"?>\r\n"+
				"<Query>\r\n"+
				"<CmdType>Catalog</CmdType>\r\n"+
				"<SN>%d</SN>\r\n"+
				"<DeviceID>%s</DeviceID>\r\n"+
				"<StartNum>1</StartNum>\r\n"+
				"<Limit>%d</Limit>\r\n"+
				"</Query>",
			config.DeviceID, config.DomainID,
			config.LocalIP, config.LocalPort, time.Now().UnixNano(),
			config.DeviceID, config.DomainID, time.Now().UnixNano()%1000000000,
			config.DeviceID, config.DomainID,
			time.Now().UnixNano()%1000000000,
			sn,
			config.DeviceID,
			state.TotalDevices,
		)
	}
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
 * @Name SendImageInfoInChunks
 * @Description 分片发送包含图片数据的 INFO 请求
 * @param conn UDP连接
 * @param serverAddr 服务器地址
 * @param config 客户端配置
 * @param imageBase64 图片的base64编码数据
 * @param chunkSize 每个分片的大小
 * @return error
 */
func SendImageInfoInChunks(conn *net.UDPConn, serverAddr *net.UDPAddr, config *ClientConfig, imageBase64 string, chunkSize int) error {
	// 生成唯一的图片ID
	imageID := fmt.Sprintf("img_%d", time.Now().UnixNano())

	// 计算需要的分片数量
	totalLen := len(imageBase64)
	totalChunks := (totalLen + chunkSize - 1) / chunkSize

	common.Infof("开始发送图片，总大小: %d bytes, 分片数: %d", totalLen, totalChunks)

	// 逐个发送分片
	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > totalLen {
			end = totalLen
		}

		chunk := imageBase64[start:end]

		// 构建XML内容
		xmlContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Image>
    <CmdType>Image</CmdType>
    <SN>%d</SN>
    <DeviceID>%s</DeviceID>
    <ImageData>%s</ImageData>
    <ChunkIndex>%d</ChunkIndex>
    <TotalChunks>%d</TotalChunks>
    <ImageID>%s</ImageID>
</Image>`, time.Now().UnixNano()%1000000000, config.DeviceID, chunk, i, totalChunks, imageID)

		// 构建INFO请求
		infoRequest := fmt.Sprintf(
			"INFO sip:%s@%s SIP/2.0\r\n"+
				"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
				"From: <sip:%s@%s>;tag=%d\r\n"+
				"To: <sip:%s@%s>\r\n"+
				"Call-ID: %s_%d\r\n"+
				"CSeq: %d INFO\r\n"+
				"Content-Type: Application/MANSCDP+xml\r\n"+
				"Max-Forwards: 70\r\n"+
				"User-Agent: GoSIP\r\n"+
				"Content-Length: %d\r\n\r\n%s",
			config.DeviceID, config.DomainID,
			config.LocalIP, config.LocalPort, time.Now().UnixNano(),
			config.DeviceID, config.DomainID, time.Now().UnixNano()%1000000000,
			config.DeviceID, config.DomainID,
			imageID, i,
			i+1,
			len(xmlContent),
			xmlContent,
		)

		// 发送当前分片
		for attempt := 0; attempt < MaxAttempts; attempt++ {
			_, err := conn.WriteToUDP([]byte(infoRequest), serverAddr)
			if err != nil {
				common.Errorf("分片 %d/%d 第%d次发送失败: %v", i+1, totalChunks, attempt+1, err)
				time.Sleep(time.Second * time.Duration(attempt+1))
				continue
			}
			common.Infof("分片 %d/%d 发送成功 %#v", i+1, totalChunks, xmlContent)
			// time.Sleep(50 * time.Millisecond) // 添加短暂延迟，避免发送过快
			break
		}
	}

	common.Infof("图片 %s 所有分片发送完成", imageID)
	return nil
}

/**
 * @Name receiveAndParseCatalogResponse
 * @Description 接收并解析目录响应
 * @param conn UDP连接
 * @return error
 */
func receiveAndParseCatalogResponse(conn *net.UDPConn, state *QueryState) error {

	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			common.Warnf("接收目录响应超时: %v", err)
			return fmt.Errorf("接收目录响应超时")
		}
		common.Errorf("从UDP读取时发生错误: %v", err)
		return fmt.Errorf("读取错误: %v", err)
	}

	response := string(buffer[:n])
	common.Debugf("收到的响应: %s", response)

	xmlContent := extractXMLContent(response)
	if xmlContent == "" {
		common.Warn("响应中未包含XML内容")
		return fmt.Errorf("无效响应")
	}

	var catalogResponse CatalogResponse
	err = parseXML(xmlContent, &catalogResponse)
	if err != nil {
		common.Errorf("解析目录响应XML时发生错误: %v", err)
		return fmt.Errorf("解析错误: %v", err)
	}

	common.Infof("解析的目录响应: 总设备数: %d, 设备列表: %d", catalogResponse.SumNum, len(catalogResponse.DeviceList.Item))
	// 更新状态，保护临界区
	// state.Lock()
	// defer state.Unlock()
	// 更新状态``
	if !state.FirstStageComplete {
		state.TotalDevices = catalogResponse.SumNum
		state.DeviceList = catalogResponse.DeviceList.Item
		if state.TotalDevices > 0 {
			state.FirstStageComplete = true
		}
	} else {
		state.DeviceList = append(state.DeviceList, catalogResponse.DeviceList.Item...)
	}

	common.Infof("更新后 TotalDevices: %d, DeviceList 长度: %d", state.TotalDevices, len(state.DeviceList))
	return nil
}

/**
 * @Name ParseAndLogResponse
 * @Description 解析并记录响应
 * @param xmlContent XML内容
 * @return error
 */
func ParseAndLogResponse(xmlContent string) error {
	if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
		var catalog CatalogResponse
		if err := parseXML(xmlContent, &catalog); err != nil {
			return fmt.Errorf("解析目录XML错误: %v", err)
		}
		common.Infof("目录响应 - 命令类型: %s, 序列号: %d, 设备ID: %s, 总数: %d",
			catalog.CmdType, catalog.SN, catalog.DeviceID, catalog.SumNum)
		for _, device := range catalog.DeviceList.Item {
			common.Infof("设备ID: %s, 名称: %s, 连接状态: %s", device.DeviceID, device.Name, device.Status)
		}
	} else if strings.Contains(xmlContent, "<CmdType>Keepalive</CmdType>") {
		var keepalive KeepaliveNotify
		if err := parseXML(xmlContent, &keepalive); err != nil {
			return fmt.Errorf("解析保活XML错误: %v", err)
		}
		common.Infof("保活 - 设备ID: %s, 状态: %s", keepalive.DeviceID, keepalive.Status)
		for _, deviceID := range keepalive.Info.DeviceIDs {
			common.Infof("设备ID: %s", deviceID)
		}
	} else {
		common.Warn("未知响应类型")
		return fmt.Errorf("未知响应类型")
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
		switch strings.ToLower(charset) {
		case "gb2312", "gbk":
			return transform.NewReader(input, simplifiedchinese.GB18030.NewDecoder()), nil
		case "utf-8":
			return input, nil
		default:
			return nil, fmt.Errorf("不支持的字符集: %s", charset)
		}
	}
	return decoder.Decode(v)
}

/**
 * @Name performCatalogQuery
 * @Description 执行完整的目录查询流程，包括第一阶段和第二阶段的查询。
 * @param conn UDP连接
 * @param nvrAddr NVR地址
 * @param config 客户端配置
 * @param state 查询状态
 * @return error
 */
func performCatalogQuery(conn *net.UDPConn, nvrAddr *net.UDPAddr, config *ClientConfig, state *QueryState) error {
	// 第一阶段查询
	err := sendCatalogQuery(conn, nvrAddr, config, state)
	if err != nil {
		return fmt.Errorf("第一阶段查询失败: %v", err)
	}

	// 等待第一阶段响应
	for i := 0; i < MaxAttempts; i++ {
		err = receiveAndParseCatalogResponse(conn, state)
		if err == nil && state.FirstStageComplete {

			break
		}
		common.Errorf("第一阶段查询第%d次尝试: %v", i+1, err)
		time.Sleep(5 * time.Second)
	}
	fmt.Println("---------第一阶段查询完成", len(state.DeviceList))

	// 仅在设备总数大于初始查询限制时执行第二阶段查询
	fmt.Println("---------state.TotalDevices", state.TotalDevices)
	fmt.Println("---------state.DeviceList", len(state.DeviceList))
	fmt.Println("---------state.FirstStageComplete", state.FirstStageComplete)
	if state.FirstStageComplete && len(state.DeviceList) < state.TotalDevices {
		err = sendCatalogQuery(conn, nvrAddr, config, state)
		if err != nil {
			return fmt.Errorf("第二阶段查询失败: %v", err)
		}

		// 等待第二阶段响应
		err = receiveAndParseCatalogResponse(conn, state)
		if err == nil {
			// 处理完整的设备列表
			common.Infof("查询完成，共发现 %d 个设备", len(state.DeviceList))
			for _, device := range state.DeviceList {
				common.Infof("设备详情 - ID: %s, 名称: %s, 连接状态: %s",
					device.DeviceID, device.Name, device.Status)
			}
		} else {
			return fmt.Errorf("第二阶段响应接收失败: %v", err)
		}
	} else {
		// 如果第一阶段已完成且设备数量已全部获取
		common.Infof("查询完成，共发现 %d 个设备", len(state.DeviceList))
		for _, device := range state.DeviceList {
			common.Infof("设备详情 - ID: %s, 名称: %s, 连接状态: %s",
				device.DeviceID, device.Name, device.Status)
		}
	}

	return nil
}

/**
 * @Name Getdevice
 * @Description 初始化UDP通信
 * @param t 协议类型
 * @param addr 地址
 */
// 重构Getdevice函数，增加配置支持
func Getdevice(configPath string) {
	Config_client, Err = LoadClientConfig(configPath)
	if Err != nil {
		common.Errorf("加载配置失败: %v", Err)
		return
	}

	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", Config_client.LocalIP, Config_client.LocalPort))
	if err != nil {
		common.Errorf("解析本地地址时发生错误: %v", err)
		return
	}

	Conn, Err = net.ListenUDP("udp", localAddr)
	if err != nil {
		common.Errorf("监听端口时发生错误: %v", err)
		return
	}
	defer Conn.Close()

	common.Info("正在监听传入消息...")

	// var NvrAddr *net.UDPAddr 转为全局变量
	for NvrAddr == nil {
		NvrAddr, err = HandleIncomingMessage(Conn, Config_client)
		if err != nil {
			common.Error(err)
		}
	}

	state := NewQueryState()

	common.Info("与服务器通信已建立。正在发送目录查询...")

	// 执行目录查询
	err = performCatalogQuery(Conn, NvrAddr, Config_client, state)
	if err != nil {
		common.Errorf("目录查询失败: %v", err)
		return
	}
	/********************info的请求处理***********************************************************************************************/

	// 在需要发送图片数据的地方调用
	// imageBase64 := "data:image/jpeg;base64,/9j/4AAQSkZ..." // 你的base64图片数据 //人脸大小9k传输失败 4k可行
	// 你的base64图片数据
	imageBase64 := `
	data:image/png;base64,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
	`
	// err = SendImageInfo(Conn, NvrAddr, Config_client, imageBase64)
	// 发送大图片时使用
	err = SendImageInfoInChunks(Conn, NvrAddr, Config_client, imageBase64, 1024*1) // 8KB per chunk
	if err != nil {
		common.Errorf("发送图片信息失败: %v", err)
	}
	/********************info的请求处理******************************************************************************/

	// 持续监听消息
	for {
		_, err := HandleIncomingMessage(Conn, Config_client)
		if err != nil {
			common.Errorf("消息处理错误: %v", err)
		}
	}
}
