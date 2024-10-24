// package main

// import (
// 	"bytes"
// 	"encoding/xml"
// 	"fmt"
// 	"io"
// 	"net"
// 	"strings"
// 	"sync"
// 	"time"

// 	"golang.org/x/text/encoding/simplifiedchinese"
// 	"golang.org/x/text/transform"
// )

// // ErrorCode 定义错误码
// type ErrorCode int

// const (
// 	Success ErrorCode = iota
// 	ErrorPlatformOffline
// 	ErrorSIPFailed
// 	ErrorTimeout
// 	ErrorBusy
// 	ErrorItemPartial
// 	ErrorWaiting
// 	ErrorSIPInvited
// 	ErrorSIPInvitedAcked
// 	ErrorSIPInvitedAckedTimeout
// 	ErrorPTZMarshalFailed
// )

// // PlayStatus 定义播放状态
// type PlayStatus int

// const (
// 	Idle PlayStatus = iota
// 	Invited
// 	InvitedTimeout
// 	InvitedAcked
// 	InvitedAckedTimeout
// )

// // Device 表示从XML中解析出的单个设备信息
// type Device struct {
// 	DeviceID     string `xml:"DeviceID"`     // 设备ID
// 	Name         string `xml:"Name"`         // 设备名称
// 	Manufacturer string `xml:"Manufacturer"` // 制造商
// 	ParentID     string `xml:"ParentID"`     // 父设备ID
// }

// // CatalogResponse 表示XML中的目录响应结构
// type CatalogResponse struct {
// 	CmdType    string `xml:"CmdType"`
// 	SN         int    `xml:"SN"`
// 	DeviceID   string `xml:"DeviceID"`
// 	SumNum     int    `xml:"SumNum"`
// 	DeviceList struct {
// 		Item []Device `xml:"Item"`
// 	} `xml:"DeviceList"`
// }

// // DeviceManager 管理设备状态和拓扑关系
// type DeviceManager struct {
// 	devices          map[string]*Device     // 所有设备的映射
// 	leafDevices      map[string]*Device     // 叶子节点设备的映射
// 	catalogBusy      bool                   // 是否正在进行目录查询
// 	catalogPlatformID string                // 当前查询的平台ID
// 	lastCatalogTime  time.Time             // 最后一次查询时间
// 	deviceList       []Device              // 当前查询的设备列表
// 	deviceSumNum     int                   // 设备总数
// 	mutex            sync.RWMutex          // 读写锁
// 	getCatalogCond   *sync.Cond           // 条件变量
// }

// // StreamManager 管理流媒体会话
// type StreamManager struct {
// 	streams     map[string]*StreamInfo
// 	mutex       sync.RWMutex
// }

// // StreamInfo 流媒体会话信息
// type StreamInfo struct {
// 	PlatformID  string
// 	DeviceID    string
// 	Status      PlayStatus
// 	MediaInfo   MediaSdp
// 	CallID      int
// 	DialogID    int
// 	CreateTime  time.Time
// }

// // MediaSdp SDP信息
// type MediaSdp struct {
// 	Address    string
// 	VideoPort  int
// 	TransType  int
// 	SSRC       uint32
// }

// // Server GB28181服务器
// type Server struct {
// 	deviceManager  *DeviceManager
// 	streamManager  *StreamManager
// 	conn           *net.UDPConn
// 	localAddr      string
// }

// // NewServer 创建服务器实例
// func NewServer(localAddr string) *Server {
// 	return &Server{
// 		deviceManager:  NewDeviceManager(),
// 		streamManager:  NewStreamManager(),
// 		localAddr:      localAddr,
// 	}
// }


// // NewDeviceManager 创建设备管理器
// func NewDeviceManager() *DeviceManager {
// 	dm := &DeviceManager{
// 		devices:     make(map[string]*Device),
// 		leafDevices: make(map[string]*Device),
// 	}
// 	dm.getCatalogCond = sync.NewCond(&dm.mutex)
// 	return dm
// }

// // NewStreamManager 创建流媒体管理器
// func NewStreamManager() *StreamManager {
// 	return &StreamManager{
// 		streams: make(map[string]*StreamInfo),
// 	}
// }

// // Run 运行服务器
// func (s *Server) Run() error {
// 	addr, err := net.ResolveUDPAddr("udp", s.localAddr)
// 	if err != nil {
// 		return fmt.Errorf("解析地址错误: %v", err)
// 	}

// 	s.conn, err = net.ListenUDP("udp", addr)
// 	if err != nil {
// 		return fmt.Errorf("监听UDP错误: %v", err)
// 	}
// 	defer s.conn.Close()

// 	fmt.Printf("服务器正在监听 %s...\n", s.localAddr)

// 	// 启动定期查询协程
// 	go s.periodicCatalogQuery()

// 	// 主消息处理循环
// 	buffer := make([]byte, 4096)
// 	for {
// 		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
// 		if err != nil {
// 			fmt.Printf("读取UDP数据错误: %v\n", err)
// 			continue
// 		}

// 		message := string(buffer[:n])
// 		go s.handleMessage(remoteAddr, message)
// 	}
// }

// // periodicCatalogQuery 定期发送目录查询
// func (s *Server) periodicCatalogQuery() {
// 	ticker := time.NewTicker(30 * time.Second)
// 	defer ticker.Stop()

// 	for range ticker.C {
// 		s.deviceManager.mutex.RLock()
// 		for deviceID := range s.deviceManager.devices {
// 			s.sendCatalogQuery(deviceID)
// 		}
// 		s.deviceManager.mutex.RUnlock()
// 	}
// }

// // handleMessage 处理接收到的消息
// func (s *Server) handleMessage(remoteAddr *net.UDPAddr, message string) {
// 	if strings.Contains(message, "REGISTER sip:") {
// 		s.handleRegister(remoteAddr, message)
// 	} else if strings.Contains(message, "<?xml") {
// 		s.handleXMLMessage(remoteAddr, message)
// 	}
// }

// // handleRegister 处理注册消息
// func (s *Server) handleRegister(remoteAddr *net.UDPAddr, message string) {
// 	response := buildSIPResponse(message, "200 OK")
// 	s.sendResponse(remoteAddr, response)

// 	// 发送初始目录查询
// 	time.Sleep(time.Second)
// 	deviceID := extractDeviceIDFromRegister(message)
// 	s.sendCatalogQuery(deviceID)
// }

// // handleXMLMessage 处理XML消息
// func (s *Server) handleXMLMessage(remoteAddr *net.UDPAddr, message string) {
// 	xmlContent := extractXMLContent(message)
// 	if xmlContent == "" {
// 		return
// 	}

// 	if strings.Contains(xmlContent, "<CmdType>Catalog</CmdType>") {
// 		var catalog CatalogResponse
// 		if err := parseXML(xmlContent, &catalog); err != nil {
// 			fmt.Printf("解析目录响应错误: %v\n", err)
// 			return
// 		}

// 		s.deviceManager.UpdateDevices(catalog.DeviceList.Item)

// 		response := buildSIPResponse(message, "200 OK")
// 		s.sendResponse(remoteAddr, response)
// 	}
// }

// // GetDeviceTree 获取设备树
// func (s *Server) GetDeviceTree(platformID string, timeout time.Duration) ([]Device, int, ErrorCode) {
// 	return s.deviceManager.GetDeviceTree(platformID, timeout)
// }

// // UpdateDevices 更新设备列表
// func (dm *DeviceManager) UpdateDevices(newDevices []Device) {
// 	dm.mutex.Lock()
// 	defer dm.mutex.Unlock()

// 	// 更新设备列表
// 	dm.deviceList = append(dm.deviceList, newDevices...)
	
// 	// 清除现有的叶子节点映射
// 	dm.leafDevices = make(map[string]*Device)
	
// 	// 更新设备映射和识别叶子节点
// 	childrenCount := make(map[string]int)
// 	for _, device := range newDevices {
// 		deviceCopy := device
// 		dm.devices[device.DeviceID] = &deviceCopy
// 		if device.ParentID != "" {
// 			childrenCount[device.ParentID]++
// 		}
// 	}

// 	// 识别叶子节点
// 	for _, device := range dm.devices {
// 		if childrenCount[device.DeviceID] == 0 {
// 			dm.leafDevices[device.DeviceID] = device
// 		}
// 	}

// 	// 打印叶子节点信息
// 	fmt.Println("\n当前叶子节点设备:")
// 	for _, device := range dm.leafDevices {
// 		fmt.Printf("设备ID: %s, 名称: %s, 制造商: %s\n",
// 			device.DeviceID, device.Name, device.Manufacturer)
// 	}

// 	// 通知等待的goroutine
// 	dm.getCatalogCond.Broadcast()
// }

// // GetDeviceTree 获取设备树的具体实现
// func (dm *DeviceManager) GetDeviceTree(platformID string, timeout time.Duration) ([]Device, int, ErrorCode) {
// 	dm.mutex.Lock()

// 	// 检查是否有其他请求正在处理
// 	if dm.catalogBusy && dm.catalogPlatformID != platformID {
// 		if time.Since(dm.lastCatalogTime) < timeout {
// 			dm.mutex.Unlock()
// 			return nil, 0, ErrorBusy
// 		}
// 		dm.catalogBusy = false
// 	}

// 	if !dm.catalogBusy {
// 		dm.catalogBusy = true
// 		dm.catalogPlatformID = platformID
// 		dm.lastCatalogTime = time.Now()
// 		dm.deviceList = nil
// 		dm.deviceSumNum = 0
// 	}

// 	// 等待结果或超时
// 	timeoutChan := time.After(timeout)
// 	done := make(chan struct{})
	
// 	go func() {
// 		for dm.deviceSumNum == 0 || len(dm.deviceList) < dm.deviceSumNum {
// 			dm.getCatalogCond.Wait()
// 		}
// 		close(done)
// 	}()

// 	dm.mutex.Unlock()

// 	select {
// 	case <-done:
// 		dm.mutex.Lock()
// 		defer dm.mutex.Unlock()
// 		dm.catalogBusy = false
// 		return dm.deviceList, dm.deviceSumNum, Success

// 	case <-timeoutChan:
// 		dm.mutex.Lock()
// 		defer dm.mutex.Unlock()
// 		if dm.deviceSumNum > 0 {
// 			return dm.deviceList, dm.deviceSumNum, ErrorItemPartial
// 		}
// 		dm.catalogBusy = false
// 		return nil, 0, ErrorTimeout
// 	}
// }

// // 辅助函数
// func buildSIPResponse(originalMessage, status string) string {
// 	return fmt.Sprintf("SIP/2.0 %s\r\n"+
// 		"Via: %s\r\n"+
// 		"From: %s\r\n"+
// 		"To: %s\r\n"+
// 		"Call-ID: %s\r\n"+
// 		"CSeq: %s\r\n"+
// 		"User-Agent: GoSIP\r\n"+
// 		"Content-Length: 0\r\n\r\n",
// 		status,
// 		extractHeader(originalMessage, "Via:"),
// 		extractHeader(originalMessage, "From:"),
// 		extractHeader(originalMessage, "To:"),
// 		extractHeader(originalMessage, "Call-ID:"),
// 		extractHeader(originalMessage, "CSeq:"))
// }

// func (s *Server) sendResponse(addr *net.UDPAddr, response string) {
// 	_, err := s.conn.WriteToUDP([]byte(response), addr)
// 	if err != nil {
// 		fmt.Printf("发送响应错误: %v\n", err)
// 	}
// }

// func extractDeviceIDFromRegister(message string) string {
// 	if start := strings.Index(message, "sip:"); start != -1 {
// 		if end := strings.Index(message[start:], "@"); end != -1 {
// 			return message[start+4 : start+end]
// 		}
// 	}
// 	return ""
// }

// func extractHeader(message, header string) string {
// 	lines := strings.Split(message, "\r\n")
// 	for _, line := range lines {
// 		if strings.HasPrefix(line, header) {
// 			return strings.TrimPrefix(line, header+" ")
// 		}
// 	}
// 	return ""
// }

// func extractXMLContent(message string) string {
// 	if start := strings.Index(message, "<?xml"); start != -1 {
// 		return message[start:]
// 	}
// 	return ""
// }

// func parseXML(xmlContent string, v interface{}) error {
// 	decoder := xml.NewDecoder(bytes.NewReader([]byte(xmlContent)))
// 	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
// 		if strings.ToLower(charset) == "gb2312" {
// 			return transform.NewReader(input, simplifiedchinese.GB18030.NewDecoder()), nil
// 		}
// 		return input, nil
// 	}
// 	return decoder.Decode(v)
// }

// // sendCatalogQuery 向指定设备发送目录查询
// func (s *Server) sendCatalogQuery(deviceID string) {
// 	// 修改为匹配NVR配置的查询消息
// 	query := fmt.Sprintf(`MESSAGE sip:%s@620100000 SIP/2.0
// Via: SIP/2.0/UDP %s;rport;branch=z9hG4bK%d
// From: <sip:62010000002000000001@620100000>;tag=%d
// To: <sip:340200000011100000011@620100000>
// Call-ID: %d
// CSeq: 20 MESSAGE
// Content-Type: Application/MANSCDP+xml
// Max-Forwards: 70
// User-Agent: GoSIP
// Content-Length: %d

// <?xml version="1.0"?>
// <Query>
// <CmdType>Catalog</CmdType>
// <SN>%d</SN>
// <DeviceID>340200000011100000011</DeviceID>
// </Query>`, deviceID, s.localAddr, time.Now().UnixNano(),
// 		time.Now().UnixNano(), time.Now().UnixNano(),
// 		164, time.Now().UnixNano())

// 	addr, err := net.ResolveUDPAddr("udp", "100.100.155.157:5060")
// 	if err != nil {
// 		fmt.Printf("解析地址错误: %v\n", err)
// 		return
// 	}

// 	_, err = s.conn.WriteToUDP([]byte(query), addr)
// 	if err != nil {
// 		fmt.Printf("发送目录查询错误: %v\n", err)
// 	}
// }

// func main() {
// 	server := NewServer("100.100.155.157:5060")
// 	if err := server.Run(); err != nil {
// 		fmt.Printf("服务器运行错误: %v\n", err)
// 	}

	
// }
// // func main() {
// // 	// 使用配置中的本地SIP端口
// // 	server := NewServer("0.0.0.0:5060")
// // 	if err := server.Run(); err != nil {
// // 		fmt.Printf("服务器运行错误: %v\n", err)
// // 	}
// // }