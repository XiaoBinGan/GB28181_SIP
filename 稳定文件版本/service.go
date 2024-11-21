package gb28181backup

import (
	"28181sip/common"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	Conn *net.UDPConn
	err  error
)

// Config 结构体用于加载配置文件
type Config struct {
	DeviceID          string `yaml:"device_id"`
	LocalIP           string `yaml:"local_ip"`
	LocalPort         string `yaml:"local_port"`
	ServerIP          string `yaml:"server_ip"`
	ServerPort        string `yaml:"server_port"`
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
// 调整 SendKeepalive 函数的 conn.Write 部分
// 确保 conn.Write 使用的是正确的 UDP 连接，且没有自动关闭连接。如果发送频繁，可以考虑将 conn 作为全局变量，只在程序关闭时关闭连接，而不是在每次发送后立即关闭。
// func RegisterNVR(config *Config) (*net.UDPConn, error) {
// 	serverAddr := fmt.Sprintf("%s:%s", config.ServerIP, config.ServerPort)
// 	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
// 	if err != nil {
// 		return nil, fmt.Errorf("无法解析服务器地址 %s: %v", serverAddr, err)
// 	}

// 	// 设置本地监听地址
// 	localAddr := fmt.Sprintf("%s:%s", config.LocalIP, config.LocalPort)
// 	localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
// 	if err != nil {
// 		return nil, fmt.Errorf("无法解析本地地址 %s: %v", localAddr, err)
// 	}

// 	// 初始化全局的 UDP 连接
// 	Conn, err = net.DialUDP("udp", localUDPAddr, udpAddr)
// 	if err != nil {
// 		return nil, fmt.Errorf("无法连接到服务器地址 %s: %v", serverAddr, err)
// 	}

// 	// 生成并发送 SIP REGISTER 消息
// 	// registerMessage := "REGISTER sip:" + serverAddr + " SIP/2.0\r\n" +
// 	// 	"Via: SIP/2.0/UDP " + config.LocalIP + ":" + config.LocalPort + ";rport;branch=z9hG4bK" + fmt.Sprint(time.Now().UnixNano()) + "\r\n" +
// 	// 	"From: <sip:" + config.DeviceID + "@6201000000>;tag=" + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 	// 	"To: <sip:" + config.DeviceID + "@6201000000>\r\n" +
// 	// 	"Call-ID: " + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 	// 	"CSeq: 1 REGISTER\r\n" +
// 	// 	"User-Agent: GoNVR\r\n" +
// 	// 	"Content-Length: 0\r\n\r\n"
// 	// 生成并发送 SIP REGISTER 消息上面的版本缺少concat
// 	registerMessage := "REGISTER sip:" + config.DeviceID + "@" + config.DomainID + " SIP/2.0\r\n" +
// 		"Via: SIP/2.0/UDP " + config.LocalIP + ":" + config.LocalPort + ";rport;branch=z9hG4bK" + fmt.Sprint(time.Now().UnixNano()) + "\r\n" +
// 		"From: <sip:" + config.DeviceID + "@" + config.DomainID + ">;tag=" + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 		"To: <sip:" + config.DeviceID + "@" + config.DomainID + ">\r\n" +
// 		"Call-ID: " + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 		"CSeq: 1 REGISTER\r\n" +
// 		"Contact: <sip:" + config.DeviceID + "@" + config.LocalIP + ":" + config.LocalPort + ">\r\n" +
// 		"Max-Forwards: 70\r\n" +
// 		"User-Agent: Embedded Net DVR/NVR/DVS\r\n" + // 修改为与实际设备一致
// 		"Expires: 86400\r\n" + // 添加过期时间，24小时
// 		"Content-Length: 0\r\n\r\n"

// 	_, err = Conn.Write([]byte(registerMessage))
// 	if err != nil {
// 		return nil, fmt.Errorf("发送注册消息时出错: %v", err)
// 	}
// 	common.Infof("已发送注册消息至 %s", serverAddr)

// 	// 接收注册响应
// 	responseBuffer := make([]byte, 4096)
// 	Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
// 	n, err := Conn.Read(responseBuffer)
// 	if err != nil {
// 		return nil, fmt.Errorf("接收注册响应时出错: %v", err)
// 	}
// 	response := string(responseBuffer[:n])

//		if !strings.Contains(response, "200 OK") {
//			return nil, fmt.Errorf("注册失败，响应: %s", response)
//		}
//		common.Info("成功注册到服务器，收到200 OK响应")
//		return Conn, nil
//	}
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
		config.DeviceID, config.DomainID,
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

	// 接收401响应
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	response := string(buffer[:n])

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
		config.DeviceID, config.DomainID,
		config.LocalIP, config.LocalPort, branch,
		config.DeviceID, config.DomainID, tag,
		config.DeviceID, config.DomainID,
		callID,
		config.DeviceID, config.LocalIP, config.LocalPort,
		config.DeviceID, realm, nonce, config.DeviceID, config.DomainID, response,
	)

	// 发送认证注册请求
	_, err = conn.Write([]byte(authenticatedRegister))
	if err != nil {
		return nil, fmt.Errorf("发送认证注册请求失败: %v", err)
	}

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
// func SendKeepalive(config *Config) error {
// 	serverAddr := fmt.Sprintf("%s:%s", config.ServerIP, config.ServerPort)
// 	conn, err := net.Dial("udp", serverAddr)
// 	if err != nil {
// 		return fmt.Errorf("无法连接到服务器地址 %s: %v", serverAddr, err)
// 	}
// 	defer conn.Close()

// 	// 生成保活消息
// 	// 有点问题
// 	// keepaliveMessage := "MESSAGE sip:" + serverAddr + " SIP/2.0\r\n" +
// 	// 	"Via: SIP/2.0/UDP " + config.LocalIP + ":" + config.LocalPort + ";rport;branch=z9hG4bK" + fmt.Sprint(time.Now().UnixNano()) + "\r\n" +
// 	// 	"From: <sip:" + config.DeviceID + "@6201000000>;tag=" + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 	// 	"To: <sip:" + config.DeviceID + "@6201000000>\r\n" +
// 	// 	"Call-ID: " + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 	// 	"CSeq: 1 MESSAGE\r\n" +
// 	// 	"Content-Type: Application/MANSCDP+xml\r\n" +
// 	// 	"User-Agent: GoNVR\r\n" +
// 	// 	"Content-Length: 150\r\n" +
// 	// 	"\r\n" +
// 	// 	"<?xml version=\"1.0\" encoding=\"gb2312\"?>\r\n" +
// 	// 	"<Notify>\r\n" +
// 	// 	"<CmdType>Keepalive</CmdType>\r\n" +
// 	// 	"<SN>1</SN>\r\n" +
// 	// 	"<DeviceID>" + config.DeviceID + "</DeviceID>\r\n" +
// 	// 	"<Status>OK</Status>\r\n" +
// 	// 	"</Notify>"
// 	keepaliveMessage := "MESSAGE sip:" + serverAddr + " SIP/2.0\r\n" +
// 		"Via: SIP/2.0/UDP " + config.LocalIP + ":" + config.LocalPort + ";rport;branch=z9hG4bK" + fmt.Sprint(time.Now().UnixNano()) + "\r\n" +
// 		"From: <sip:" + config.DeviceID + "@6201000000>;tag=" + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 		"To: <sip:" + config.DeviceID + "@6201000000>\r\n" +
// 		"Call-ID: " + fmt.Sprint(time.Now().UnixNano()%1000000000) + "\r\n" +
// 		"CSeq: 1 MESSAGE\r\n" +
// 		"Content-Type: Application/MANSCDP+xml\r\n" +
// 		"User-Agent: GoNVR\r\n" +
// 		"Content-Length: 150\r\n" +
// 		"\r\n" +
// 		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" +
// 		"<Notify>\r\n" +
// 		"<CmdType>Keepalive</CmdType>\r\n" +
// 		"<SN>1</SN>\r\n" +
// 		"<DeviceID>" + config.DeviceID + "</DeviceID>\r\n" +
// 		"<Status>OK</Status>\r\n" +
// 		"</Notify>"

// 	_, err = conn.Write([]byte(keepaliveMessage))
// 	if err != nil {
// 		return fmt.Errorf("发送保活消息时出错: %v", err)
// 	}
// 	common.Info("已发送保活消息")

//		return nil
//	}
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
	// keepaliveMessage := fmt.Sprintf(
	// 	"MESSAGE sip:%s@%s SIP/2.0\r\n"+
	// 		"Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%d\r\n"+
	// 		"From: <sip:%s@6201000000>;tag=%d\r\n"+
	// 		"To: <sip:%s@6201000000>\r\n"+
	// 		"Call-ID: %d\r\n"+
	// 		"CSeq: 20 MESSAGE\r\n"+
	// 		"Content-Type: Application/MANSCDP+xml\r\n"+
	// 		"Max-Forwards: 70\r\n"+ // 添加了Max-Forwards
	// 		"User-Agent: Embedded Net DVR/NVR/DVS\r\n"+ // 修改了User-Agent
	// 		//"User-Agent: GoNVR\r\n"+
	// 		"Content-Length: %d\r\n\r\n%s",
	// 	config.ServerIP, config.ServerPort,
	// 	config.LocalIP, config.LocalPort, time.Now().UnixNano(),
	// 	config.DeviceID, time.Now().UnixNano()%1000000000,
	// 	config.DeviceID,
	// 	time.Now().UnixNano()%1000000000,
	// 	contentLength,
	// 	xmlBody,
	// )
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

	ticker := time.NewTicker(time.Duration(config.KeepaliveInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := SendKeepalive(config)
			if err != nil {
				common.Errorf("发送保活失败: %v", err)
			}
		}
	}
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
