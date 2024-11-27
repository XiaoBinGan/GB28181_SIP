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
	DeviceID  string
	Name      string
	Status    string
	Longitude string
	Latitude  string
	Address   string
}

/******************************************************test add **********************************************************************/

// Config 结构体用于加载配置文件
type Config struct {
	DeviceID          string `yaml:"device_id"`
	LocalIP           string `yaml:"local_ip"`
	LocalPort         string `yaml:"local_port"`
	ServerIP          string `yaml:"server_ip"`
	ServerPort        string `yaml:"server_port"`
	ServerID          string `yaml:"server_id"`
	DomainID          string `yaml:"domain_id"` // 添加域ID配置
	KeepaliveInterval int    `yaml:"keepalive_interval"`
	Password          string `yaml:"password"`
}

// LoadConfig 从指定路径加载 YAML 配置文件
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

// RegisterNVR 向其他平台发送注册请求以伪装成NVR设备。
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

// SendKeepalive 向平台发送保活消息，模拟NVR设备在线状态。
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

// 模拟NVR设备的主程序入口 在 SimulateNVR 函数中初始化全局连接并保持运行，确保连接只关闭一次：
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

// HandleCatalog 处理接收到的Catalog消息并返回响应
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

	// 生成更可靠的分支和标签
	branch := fmt.Sprintf("z9hG4bK%d", time.Now().UnixNano())
	toTag := fmt.Sprintf("to-%d", time.Now().UnixNano())

	// 第一步：立即返回200 OK响应
	firstResponse := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Via: %s\r\n"+
			"From: <sip:%s@%s:5060>;tag=%s\r\n"+
			"To: <sip:%s@%s:%s>;tag=%s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %s MESSAGE\r\n"+
			"User-agent: Embedded Net smaiDVR/NVR/DVS\r\n"+
			"Content-Length: 0\r\n\r\n",
		// config.ServerIP, config.ServerPort, config.ServerPort, branch,
		via,
		config.ServerID, config.ServerIP, fromTag,
		config.DeviceID, config.LocalIP, config.LocalPort, toTag,
		callID,
		cseq,
	)

	// 发送200 OK响应
	_, err := Conn.Write([]byte(firstResponse))
	if err != nil {
		return fmt.Errorf("发送200 OK响应失败: %v", err)
	}

	common.Info("已发送Catalog 200 OK响应")

	// 定义完整的设备列表
	devices := []CatalogItem{
		{DeviceID: "34020000001320000021", Name: "阶梯会议厅", Status: "OFF", Address: "100.100.138.10"},
		{DeviceID: "34020000001320000002", Name: "洗手间", Status: "ON", Address: "100.100.138.13"},
		{DeviceID: "34020000001320000003", Name: "Camera 01", Status: "ON", Address: "100.100.138.18"},
		{DeviceID: "34020000001320000004", Name: "走廊1", Status: "OFF", Address: "100.100.138.12"},
		{DeviceID: "34020000001320000005", Name: "前台", Status: "OFF", Address: "100.100.138.14"},
		{DeviceID: "34020000001320000006", Name: "机房", Status: "OFF", Address: "100.100.138.15"},
		{DeviceID: "34020000001320000007", Name: "办公区1", Status: "OFF", Address: "100.100.138.11"},
		{DeviceID: "34020000001320000008", Name: "办公区2", Status: "OFF", Address: "100.100.138.16"},
		{DeviceID: "34020000001320000009", Name: "展厅1", Status: "OFF", Address: "100.100.138.19"},
		{DeviceID: "34020000001320000010", Name: "展厅2", Status: "OFF", Address: "100.100.138.20"},
		{DeviceID: "34020000001320000013", Name: "办公区3", Status: "OFF", Address: "100.100.138.21"},
	}

	// 构建XML响应
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
            <Owner>Owner</Owner>
            <CivilCode>CivilCode</CivilCode>
            <Address>` + dev.Address + `</Address>
            <Parental>0</Parental>
            <SafetyWay>0</SafetyWay>
            <RegisterWay>1</RegisterWay>
            <Secrecy>0</Secrecy>
            <Status>` + dev.Status + `</Status>
        </Item>`)
	}

	deviceListXML.WriteString(`
    </DeviceList>
</Response>`)

	xmlBody := deviceListXML.String()
	contentLength := len(xmlBody)

	// 构建发送设备列表的消息
	deviceListMessage := fmt.Sprintf(
		"MESSAGE sip:%s@%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:%s;rport;branch=%s\r\n"+
			"From: <sip:%s@%s>;tag=%s\r\n"+
			"To: <sip:%s@%s>;tag=%s\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %d MESSAGE\r\n"+
			"Content-Type: Application/MANSCDP+xml\r\n"+
			"Max-Forwards: 70\r\n"+
			"User-Agent: Embedded Net DVR/NVR/DVS\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		config.DeviceID, config.DomainID,
		config.LocalIP, config.LocalPort, branch,
		config.DeviceID, config.DomainID, fromTag,
		config.DeviceID, config.DomainID, toTag,
		callID,
		rand.Int63n(10000),
		contentLength,
		xmlBody,
	)

	// 发送设备列表消息
	_, err = Conn.Write([]byte(deviceListMessage))
	if err != nil {
		return fmt.Errorf("发送设备列表消息失败: %v", err)
	}

	common.Info("已发送设备列表消息")
	return nil
}

// 解释

// 	1.	Config 结构体: 定义配置参数的结构体，包含设备ID、本地和服务器IP地址、端口等。
// 	2.	LoadConfig 函数: 从 YAML 文件 config.yaml 中加载配置参数。
// 	3.	RegisterNVR 和 SendKeepalive 函数: 使用 Config 参数代替硬编码的信息。
// 	4.	SimulateNVR 函数: 接收配置文件路径参数，加载配置并运行主逻辑。

// 这样，修改配置只需编辑 config.yaml 文件即可，而无需更改代码。

// 我们可以将硬编码的配置（如DeviceID、NVRPort等）提取出来，并使用配置文件或环境变量的方式灵活设置这些参数。这样在不同的运行环境中可以使用不同的配置而无需修改代码。

// 以下是改进版本的nvr_simulator.go，使用配置结构体来加载外部参数：

// 新增配置文件

// 创建一个配置文件 config.yaml，用于定义设备信息和服务器地址等参数：

// # config.yaml
// device_id: "34020000001110000011"
// local_ip: "100.100.155.157"
// local_port: "5061" # 本地NVR模拟的端口
// server_ip: "192.168.1.100" # 服务器的IP地址
// server_port: "5060" # 服务器的端口
// keepalive_interval: 30 # 保活消息的发送间隔（秒）

// 更新代码 nvr_simulator.go

// 在新的代码中，我们增加了 Config 结构体，并从配置文件中读取参数，取代硬编码的配置。
