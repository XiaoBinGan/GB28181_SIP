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
	"sync"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"gopkg.in/yaml.v2"
)

// 查询状态结构体
type QueryState struct {
	sync.Mutex         //加锁确保数线程安全
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

// LoadClientConfig 从YAML文件加载配置
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
	state.Lock()
	defer state.Unlock()
	// 更新状态
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
	config, err := LoadClientConfig(configPath)
	if err != nil {
		common.Errorf("加载配置失败: %v", err)
		return
	}

	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", config.LocalIP, config.LocalPort))
	if err != nil {
		common.Errorf("解析本地地址时发生错误: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		common.Errorf("监听端口时发生错误: %v", err)
		return
	}
	defer conn.Close()

	common.Info("正在监听传入消息...")

	var nvrAddr *net.UDPAddr
	for nvrAddr == nil {
		nvrAddr, err = HandleIncomingMessage(conn, config)
		if err != nil {
			common.Error(err)
		}
	}

	state := NewQueryState()
	// state := &QueryState{
	// 	FirstStageComplete: false,
	// 	DeviceList:         []Device{},
	// 	TotalDevices:       0,
	// }

	common.Info("与服务器通信已建立。正在发送目录查询...")

	// 执行目录查询
	err = performCatalogQuery(conn, nvrAddr, config, state)
	if err != nil {
		common.Errorf("目录查询失败: %v", err)
		return
	}

	// 持续监听消息
	for {
		_, err := HandleIncomingMessage(conn, config)
		if err != nil {
			common.Errorf("消息处理错误: %v", err)
		}
	}
}
