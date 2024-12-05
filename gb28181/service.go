package gb28181

import (
	"28181sip/common"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	Conn *net.UDPConn
	// err  error
)

/******************************************************test add **********************************************************************/

// Catalog 结构体用于存储设备目录信息
type CatalogItem struct {
	DeviceID  string //设备ID
	Name      string //设备名称
	Status    string //设备状态
	Longitude string //经度
	Latitude  string //纬度
	Address   string //地址
}

/******************************************************test add **********************************************************************/

// Config 结构体用于加载配置文件
type Config struct {
	DeviceID          string `yaml:"device_id"`          //本地NVR模拟的ID
	LocalIP           string `yaml:"local_ip"`           //本地NVR模拟的IP地址
	LocalPort         string `yaml:"local_port"`         //本地NVR模拟的端口
	ServerIP          string `yaml:"server_ip"`          //服务器的IP地址
	ServerPort        string `yaml:"server_port"`        //服务器的端口
	ServerID          string `yaml:"server_id"`          //服务器的ID
	DomainID          string `yaml:"domain_id"`          // 添加域ID配置
	KeepaliveInterval int    `yaml:"keepalive_interval"` //心跳间隔时间
	Password          string `yaml:"password"`           //密码
}

/**
 * @Name: LoadConfig
 * @Description:LoadConfig 从指定路径加载 YAML 配置文件
 * @param path
 * @return *Config
 * @return error
 */
func LoadConfig(path string) (*Config, error) {
	config := &Config{}
	data, err := ioutil.ReadFile(path)
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
 * @Name: RegisterNVR
 * @Description:RegisterNVR 向其他平台发送注册请求以伪装成NVR设备。
 * @param config
 * @return net.UDPConn
 * @return error
 */
func RegisterNVR(config *Config) (*net.UDPConn, error) {
	// 设置连接
	serverAddr := fmt.Sprintf("%s:%s", config.ServerIP, config.ServerPort)
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("无法解析服务器地址: %v", err)
	}

	localAddr := fmt.Sprintf("%s:%s", config.LocalIP, config.LocalPort)
	localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("无法解析本地地址: %v", err)
	}

	conn, err := net.DialUDP("udp", localUDPAddr, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %v", err)
	}

	// 生成第一次REGISTER消息
	callID := fmt.Sprint(time.Now().UnixNano() % 1000000000)
	tag := fmt.Sprint(time.Now().UnixNano() % 1000000000)
	branch := fmt.Sprint(time.Now().UnixNano())

	firstRegister := fmt.Sprintf(
		"REGISTER sip:%s@%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%s\r\n"+
			"From: <sip:%s@%s>;tag=%s\r\n"+
			"To: <sip:%s@%s>\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: 1 REGISTER\r\n"+
			"Contact: <sip:%s@%s:%s>\r\n"+
			"Max-Forwards: 70\r\n"+
			"User-Agent: Embedded Net DVR/NVR/DVS\r\n"+
			"Expires: 86400\r\n"+
			"Content-Length: 0\r\n\r\n",
		config.ServerID, config.DomainID,
		config.LocalIP, config.LocalPort, branch,
		config.DeviceID, config.DomainID, tag,
		config.DeviceID, config.DomainID,
		callID,
		config.DeviceID, config.LocalIP, config.LocalPort,
	)

	// 发送第一次注册请求
	_, err = conn.Write([]byte(firstRegister))
	if err != nil {
		return nil, fmt.Errorf("发送注册请求失败: %v", err)
	}
	common.Info("第一次注册消息: %s", firstRegister)

	// 接收401响应
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)

	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	response := string(buffer[:n])
	/***** 401响应处理 */
	if strings.Contains(string(buffer[:n]), "200 OK") {
		common.Info("收到的200响应: %s", response)
		return conn, nil
	}
	/***** 401响应处理 */
	common.Info("收到的401响应: %s", response)

	// 解析realm和nonce
	realmRe := regexp.MustCompile(`realm="([^"]+)"`)
	nonceRe := regexp.MustCompile(`nonce="([^"]+)"`)

	realmMatch := realmRe.FindStringSubmatch(response)
	nonceMatch := nonceRe.FindStringSubmatch(response)

	if len(realmMatch) < 2 || len(nonceMatch) < 2 {
		return nil, fmt.Errorf("无法解析认证信息")
	}

	realm := realmMatch[1]
	nonce := nonceMatch[1]

	// 生成response
	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(config.DeviceID+":"+realm+":"+config.Password)))
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte("REGISTER:sip:"+config.DeviceID+"@"+config.DomainID)))
	response = fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+nonce+":"+ha2)))

	// 生成第二次带认证的REGISTER消息
	branch = fmt.Sprint(time.Now().UnixNano())
	authenticatedRegister := fmt.Sprintf(
		"REGISTER sip:%s@%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%s\r\n"+
			"From: <sip:%s@%s>;tag=%s\r\n"+
			"To: <sip:%s@%s>\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: 2 REGISTER\r\n"+
			"Contact: <sip:%s@%s:%s>\r\n"+
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"sip:%s@%s\", response=\"%s\", algorithm=MD5\r\n"+
			"Max-Forwards: 70\r\n"+
			"User-Agent: Embedded Net DVR/NVR/DVS\r\n"+
			"Expires: 86400\r\n"+
			"Content-Length: 0\r\n\r\n",
		config.ServerID, config.DomainID,
		config.LocalIP, config.LocalPort, branch,
		config.DeviceID, config.DomainID, tag,
		config.DeviceID, config.DomainID,
		callID,
		config.DeviceID, config.LocalIP, config.LocalPort,
		config.DeviceID, realm, nonce, config.ServerID, config.DomainID, response,
	)

	// 发送认证注册请求
	_, err = conn.Write([]byte(authenticatedRegister))
	if err != nil {
		return nil, fmt.Errorf("发送认证注册请求失败: %v", err)
	}
	common.Info("第二次注册消息: %s", authenticatedRegister)

	// 接收200 OK响应
	n, err = conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取认证响应失败: %v", err)
	}
	response = string(buffer[:n])

	if !strings.Contains(response, "200 OK") {
		return nil, fmt.Errorf("注册失败，响应: %s", response)
	}
	common.Info("成功注册到服务器，收到200 OK响应")

	return conn, nil
}

/**
 * @Name: SendKeepalive
 * @Description: 向平台发送保活消息，模拟NVR设备在线状态。
 * @param config 设备配置信息
 * @return error 错误信息
 */
func SendKeepalive(config *Config) error {
	if Conn == nil {
		return fmt.Errorf("全局连接未初始化")
	}

	// 构建保活消息
	xmlBody := "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" +
		"<Notify>\r\n" +
		"<CmdType>Keepalive</CmdType>\r\n" +
		"<SN>1</SN>\r\n" +
		"<DeviceID>" + config.DeviceID + "</DeviceID>\r\n" +
		"<Status>OK</Status>\r\n" +
		"</Notify>"

	contentLength := len(xmlBody)
	keepaliveMessage := fmt.Sprintf(
		"MESSAGE sip:%s@%s SIP/2.0\r\n"+ // 修改了消息格式
			"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
			"From: ;tag=%d\r\n"+
			"To: \r\n"+
			"Call-ID: %d\r\n"+
			"CSeq: 20 MESSAGE\r\n"+ // 修改了CSeq+61
			"Content-Type: Application/MANSCDP+xml\r\n"+
			"Max-Forwards: 70\r\n"+ // 添加了Max-Forwards
			"User-Agent: Embedded Net DVR/NVR/DVS\r\n"+ // 修改了User-Agent
			"Content-Length: %d\r\n\r\n%s",
		config.DeviceID, config.ServerIP, // 修改了URI格式
		config.LocalIP, config.LocalPort,
		rand.Int63n(9999999999), // 生成分支ID
		rand.Int63n(9999999999), // 生成tag
		rand.Int63n(9999999999), // 生成Call-ID
		contentLength,
		xmlBody,
	)
	_, err := Conn.Write([]byte(keepaliveMessage))
	if err != nil {
		return fmt.Errorf("发送保活消息时出错: %v", err)
	}
	common.Info("已发送保活消息")
	return nil
}

/**
 * @Name SimulateNVR
 * @Description:  模拟NVR设备的主程序入口 在 SimulateNVR 函数中初始化全局连接并保持运行，确保连接只关闭一次：
 * @param configPath 配置文件路径
 * @return error
 */
func SimulateNVR(configPath string) {
	config, err := LoadConfig(configPath)
	if err != nil {
		common.Errorf("加载配置文件失败: %v", err)
		return
	}

	common.Info("模拟 NVR 设备启动...")
	Conn, err = RegisterNVR(config)
	if err != nil {
		common.Errorf("注册失败: %v", err)
		return
	}
	defer Conn.Close() // 确保在程序退出时关闭连接

	/******************************************************test add **********************************************************************/
	// 创建一个通道用于并发处理消息
	msgChan := make(chan string, 10)
	// 启动消息接收协程
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := Conn.Read(buffer)
			if err != nil {
				common.Errorf("读取消息失败: %v", err)
				continue
			}
			msgChan <- string(buffer[:n])
		}
	}()

	/******************************************************test add **********************************************************************/

	ticker := time.NewTicker(time.Duration(config.KeepaliveInterval) * time.Second)
	defer ticker.Stop()
	/******************************************************test add **********************************************************************/
	// 启动一个协程处理消息
	go func() {
		for {
			select {
			case msg := <-msgChan:
				common.Infof("收到消息: %s", msg)
				// 处理消息逻辑
			case <-time.After(5 * time.Minute): // 增加超时处理
				common.Warn("长时间未收到消息")
			}
		}
	}()
	/******************************************************test add **********************************************************************/

	for {
		select {
		case <-ticker.C:
			err = SendKeepalive(config)
			if err != nil {
				common.Errorf("发送保活失败: %v", err)
			}
		/******************************************************test add **********************************************************************/
		case msg := <-msgChan:
			// 判断消息类型
			if strings.Contains(msg, "CmdType>Catalog") {
				err := HandleCatalog(config, msg)
				if err != nil {
					common.Errorf("处理Catalog消息失败: %v", err)
				}
			}

		}
		/******************************************************test add **********************************************************************/

	}
}

/**
 * @Name: HandleCatalog
 * @Description:  HandleCatalog 处理接收到的 Catalog 消息并返回设备列表
 * @param config 配置信息
 * @param request 请求信息
 * @return error 错误信息
 */
func HandleCatalog(config *Config, request string) error {
	fmt.Println("收到Catalog请求")
	if Conn == nil {
		return fmt.Errorf("全局连接未初始化")
	}

	// 解析请求信息
	callIDRe := regexp.MustCompile(`Call-ID: (.+?)\r\n`)
	fromTagRe := regexp.MustCompile(`From:.*?tag=(.+?)\r\n`)
	cseqRe := regexp.MustCompile(`CSeq: (\d+)`)
	viaRe := regexp.MustCompile(`Via: (.+?)\r\n`)

	callIDMatches := callIDRe.FindStringSubmatch(request)
	fromTagMatches := fromTagRe.FindStringSubmatch(request)
	cseqMatches := cseqRe.FindStringSubmatch(request)
	viaMatches := viaRe.FindStringSubmatch(request)

	if len(callIDMatches) < 2 || len(fromTagMatches) < 2 || len(cseqMatches) < 2 || len(viaMatches) < 2 {
		return fmt.Errorf("无法解析SIP消息头")
	}

	callID := callIDMatches[1]
	fromTag := fromTagMatches[1]
	cseq := cseqMatches[1]
	via := viaMatches[1]
	fmt.Printf("via: %s\n", via)

	// 生成分支和标签
	branch := fmt.Sprintf("z9hG4bK%d", time.Now().UnixNano())
	toTag := fmt.Sprintf("to-%d", time.Now().UnixNano())

	// 返回200 OK响应
	response200 := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Via: %s\r\n"+
			"From: <sip:%s@%s>;tag=%s\r\n"+
			"To: <sip:%s@%s>;tag=%s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %s MESSAGE\r\n"+
			"Content-Length: 0\r\n\r\n",
		via,
		config.ServerID, config.ServerIP, fromTag,
		config.DeviceID, config.LocalIP, toTag,
		callID,
		cseq,
	)

	_, err := Conn.Write([]byte(response200))
	if err != nil {
		return fmt.Errorf("发送200 OK响应失败: %v", err)
	}
	common.Info("已发送Catalog 200 OK响应")

	// 构建设备列表
	devices := []CatalogItem{
		{DeviceID: "34020000001320000021", Name: "1", Status: "OFF", Address: "100.101.138.10"},
		{DeviceID: "34020000001320000002", Name: "2", Status: "ON", Address: "100.101.138.13"},
		{DeviceID: "34020000001320000003", Name: "Camera 01", Status: "ON", Address: "100.101.138.18"},
		{DeviceID: "34020000001320000004", Name: "3", Status: "OFF", Address: "100.101.138.12"},
		{DeviceID: "34020000001320000005", Name: "4", Status: "OFF", Address: "100.101.138.14"},
		{DeviceID: "34020000001320000006", Name: "5", Status: "OFF", Address: "100.101.138.15"},
		{DeviceID: "34020000001320000007", Name: "6", Status: "OFF", Address: "100.101.138.11"},
		{DeviceID: "34020000001320000008", Name: "7", Status: "OFF", Address: "100.101.138.16"},
		{DeviceID: "34020000001320000009", Name: "8", Status: "OFF", Address: "100.101.138.19"},
		{DeviceID: "34020000001320000010", Name: "9", Status: "OFF", Address: "100.101.138.20"},
		{DeviceID: "34020000001320000013", Name: "10", Status: "OFF", Address: "100.101.138.21"},
	}

	var deviceListXML strings.Builder
	deviceListXML.WriteString(`<?xml version="1.0" encoding="GB2312"?>
	<Response>
		<CmdType>Catalog</CmdType>
		<SN>1</SN>
		<DeviceID>` + config.DeviceID + `</DeviceID>
		<SumNum>` + strconv.Itoa(len(devices)) + `</SumNum>
		<DeviceList Num="` + strconv.Itoa(len(devices)) + `">`)
	for _, dev := range devices {
		deviceListXML.WriteString(`
				<Item>
					<DeviceID>` + dev.DeviceID + `</DeviceID>
					<Name>` + dev.Name + `</Name>
					<Manufacturer>Generic</Manufacturer>
					<Model>Camera</Model>
					<Address>` + dev.Address + `</Address>
					<Status>` + dev.Status + `</Status>
				</Item>`)
	}
	deviceListXML.WriteString(`
		</DeviceList>
	</Response>`)

	xmlBody := deviceListXML.String()
	contentLength := len(xmlBody)

	// 发送设备列表消息
	catalogMessage := fmt.Sprintf(
		"MESSAGE sip:%s@%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:%s;rport;branch=%s\r\n"+
			"From: <sip:%s@%s>;tag=%s\r\n"+
			"To: <sip:%s@%s>;tag=%s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %d MESSAGE\r\n"+
			"Content-Type: Application/MANSCDP+xml\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		config.ServerID, config.DomainID,
		config.LocalIP, config.LocalPort, branch,
		config.DeviceID, config.DomainID, fromTag,
		config.DeviceID, config.DomainID, toTag,
		callID,
		rand.Int63n(10000),
		contentLength,
		xmlBody,
	)

	_, err = Conn.Write([]byte(catalogMessage))
	if err != nil {
		return fmt.Errorf("发送设备列表消息失败: %v", err)
	}

	common.Info("已发送设备列表消息")
	return nil
}
