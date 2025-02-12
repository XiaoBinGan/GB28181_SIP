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
// func SendImageInfoInChunks(conn *net.UDPConn, serverAddr *net.UDPAddr, config *ClientConfig, imageBase64 string, chunkSize int) error {
// 	// 生成唯一的图片ID
// 	imageID := fmt.Sprintf("img_%d", time.Now().UnixNano())

// 	// 计算需要的分片数量
// 	totalLen := len(imageBase64)
// 	totalChunks := (totalLen + chunkSize - 1) / chunkSize

// 	common.Infof("开始发送图片，总大小: %d bytes, 分片数: %d", totalLen, totalChunks)

// 	// 逐个发送分片
// 	for i := 0; i < totalChunks; i++ {
// 		start := i * chunkSize
// 		end := start + chunkSize
// 		if end > totalLen {
// 			end = totalLen
// 		}

// 		chunk := imageBase64[start:end]

// 		// 构建XML内容
// 		xmlContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
// <Image>
//     <CmdType>Image</CmdType>
//     <SN>%d</SN>
//     <DeviceID>%s</DeviceID>
//     <ImageData>%s</ImageData>
//     <ChunkIndex>%d</ChunkIndex>
//     <TotalChunks>%d</TotalChunks>
//     <ImageID>%s</ImageID>
// </Image>`, time.Now().UnixNano()%1000000000, config.DeviceID, chunk, i, totalChunks, imageID)

// 		// 构建INFO请求
// 		infoRequest := fmt.Sprintf(
// 			"INFO sip:%s@%s SIP/2.0\r\n"+
// 				"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
// 				"From: <sip:%s@%s>;tag=%d\r\n"+
// 				"To: <sip:%s@%s>\r\n"+
// 				"Call-ID: %s_%d\r\n"+
// 				"CSeq: %d INFO\r\n"+
// 				"Content-Type: Application/MANSCDP+xml\r\n"+
// 				"Max-Forwards: 70\r\n"+
// 				"User-Agent: GoSIP\r\n"+
// 				"Content-Length: %d\r\n\r\n%s",
// 			config.DeviceID, config.DomainID,
// 			config.LocalIP, config.LocalPort, time.Now().UnixNano(),
// 			config.DeviceID, config.DomainID, time.Now().UnixNano()%1000000000,
// 			config.DeviceID, config.DomainID,
// 			imageID, i,
// 			i+1,
// 			len(xmlContent),
// 			xmlContent,
// 		)

// 		// 发送当前分片
// 		for attempt := 0; attempt < MaxAttempts; attempt++ {
// 			_, err := conn.WriteToUDP([]byte(infoRequest), serverAddr)
// 			if err != nil {
// 				common.Errorf("分片 %d/%d 第%d次发送失败: %v", i+1, totalChunks, attempt+1, err)
// 				time.Sleep(time.Second * time.Duration(attempt+1))
// 				continue
// 			}
// 			common.Infof("分片 %d/%d 发送成功 %#v", i+1, totalChunks, xmlContent)
// 			// time.Sleep(50 * time.Millisecond) // 添加短暂延迟，避免发送过快
// 			break
// 		}
// 	}

// 	common.Infof("图片 %s 所有分片发送完成", imageID)
// 	return nil
// }
/**
 * @Name SendImageInfoInChunks
 * @Description 分片发送包含轨迹信息和图片数据的 INFO 请求
 * @param conn UDP连接
 * @param serverAddr 服务器地址
 * @param config 客户端配置
 * @param trackInfo 轨迹信息
 * @param imageBase64 图片的base64编码数据
 * @param chunkSize 每个分片的大小
 * @return error
 * @TODO 其实这里还可以拆分但是内容过多  逻辑比较临时  暂时不做处理
 */
func SendImageInfoInChunks(conn *net.UDPConn, serverAddr *net.UDPAddr, config *ClientConfig, trackInfo string, imageBase64 string, chunkSize int) error {
	// 首先发送轨迹信息
	xmlTrackInfo := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Track>
    <CmdType>Track</CmdType>
    <SN>%d</SN>
    <DeviceID>%s</DeviceID>
    <TrackInfo>%s</TrackInfo>
</Track>`, time.Now().UnixNano()%1000000000, config.DeviceID, trackInfo)

	trackInfoRequest := fmt.Sprintf(
		"INFO sip:%s@%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
			"From: <sip:%s@%s>;tag=%d\r\n"+
			"To: <sip:%s@%s>\r\n"+
			"Call-ID: %s_track\r\n"+
			"CSeq: 1 INFO\r\n"+
			"Content-Type: Application/MANSCDP+xml\r\n"+
			"Max-Forwards: 70\r\n"+
			"User-Agent: GoSIP\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		config.DeviceID, config.DomainID,
		config.LocalIP, config.LocalPort, time.Now().UnixNano(),
		config.DeviceID, config.DomainID, time.Now().UnixNano()%1000000000,
		config.DeviceID, config.DomainID,
		time.Now().UnixNano(),
		len(xmlTrackInfo),
		xmlTrackInfo,
	)

	// 发送轨迹信息
	for attempt := 0; attempt < MaxAttempts; attempt++ {
		_, err := conn.WriteToUDP([]byte(trackInfoRequest), serverAddr)
		if err != nil {
			common.Errorf("轨迹信息发送失败，第%d次尝试: %v", attempt+1, err)
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		}
		common.Infof("轨迹信息发送成功")
		break
	}

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
			common.Infof("分片 %d/%d 发送成功", i+1, totalChunks)
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
	// // err = SendImageInfo(Conn, NvrAddr, Config_client, imageBase64)
	imageBase64 := `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKgAAAEsCAIAAADYf2`
	trackInfo := "{\"faceCluster\":\" 测试测试测试\",\"timeStart\":\"yyyy-MM-dd HH:mm:ss\",\"timeEnd\":\"yyyy-MM-dd HH:mm:ss\",\"threshold\":0.9}"

	// // 发送大图片时使用
	err = SendImageInfoInChunks(Conn, NvrAddr, Config_client, trackInfo, imageBase64, 1024*1) // 8KB per chunk
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

/*TODO*/

/**
 * @Name SendImageInfoInChunks
 * @Description 分片发送包含轨迹信息和图片数据的 INFO 请求
 * @param conn UDP连接
 * @param serverAddr 服务器地址
 * @param config 客户端配置
 * @param trackInfo 轨迹信息
 * @param imageBase64 图片的base64编码数据
 * @param chunkSize 每个分片的大小
 * @return error
 */
/***
 func SendImageInfoInChunks(conn *net.UDPConn, serverAddr *net.UDPAddr, config *ClientConfig, trackInfo string, imageBase64 string, chunkSize int) error {
    // 首先发送轨迹信息
    xmlTrackInfo := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Track>
    <CmdType>Track</CmdType>
    <SN>%d</SN>
    <DeviceID>%s</DeviceID>
    <TrackInfo>%s</TrackInfo>
</Track>`, time.Now().UnixNano()%1000000000, config.DeviceID, trackInfo)

    trackInfoRequest := fmt.Sprintf(
        "INFO sip:%s@%s SIP/2.0\r\n"+
            "Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
            "From: <sip:%s@%s>;tag=%d\r\n"+
            "To: <sip:%s@%s>\r\n"+
            "Call-ID: %s_track\r\n"+
            "CSeq: 1 INFO\r\n"+
            "Content-Type: Application/MANSCDP+xml\r\n"+
            "Max-Forwards: 70\r\n"+
            "User-Agent: GoSIP\r\n"+
            "Content-Length: %d\r\n\r\n%s",
        config.DeviceID, config.DomainID,
        config.LocalIP, config.LocalPort, time.Now().UnixNano(),
        config.DeviceID, config.DomainID, time.Now().UnixNano()%1000000000,
        config.DeviceID, config.DomainID,
        time.Now().UnixNano(),
        len(xmlTrackInfo),
        xmlTrackInfo,
    )

    // 发送轨迹信息
    for attempt := 0; attempt < MaxAttempts; attempt++ {
        _, err := conn.WriteToUDP([]byte(trackInfoRequest), serverAddr)
        if err != nil {
            common.Errorf("轨迹信息发送失败，第%d次尝试: %v", attempt+1, err)
            time.Sleep(time.Second * time.Duration(attempt+1))
            continue
        }
        common.Infof("轨迹信息发送成功")
        break
    }

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
            common.Infof("分片 %d/%d 发送成功", i+1, totalChunks)
            break
        }
    }

    common.Infof("图片 %s 所有分片发送完成", imageID)
    return nil
}优化成两个函数
*/
