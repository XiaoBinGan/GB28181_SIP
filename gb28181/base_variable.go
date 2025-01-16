package gb28181

import (
	"net"
)

var (
	Conn          *net.UDPConn  //UDP 全局的连接对象
	Err           error         //Error 全局的对象
	Config_client *ClientConfig //全局的client配置根据配置文件映射出来的的client config对象
	NvrAddr       *net.UDPAddr  //服务器地址全局暴露使用
)

// // ImageChunk 表示图片分片信息的结构体
// type ImageChunk struct {
// 	CmdType     string `xml:"CmdType"`     // 命令类型
// 	SN          int    `xml:"SN"`          // 序列号
// 	DeviceID    string `xml:"DeviceID"`    // 设备ID
// 	ImageData   string `xml:"ImageData"`   // 分片的base64数据
// 	ChunkIndex  int    `xml:"ChunkIndex"`  // 当前分片索引
// 	TotalChunks int    `xml:"TotalChunks"` // 总分片数
// 	ImageID     string `xml:"ImageID"`     // 图片唯一标识
// }
// type ImageData struct {
// 	XMLName     xml.Name `xml:"Image"`
// 	CmdType     string   `xml:"CmdType"`
// 	SN          int      `xml:"SN"`
// 	DeviceID    string   `xml:"DeviceID"`
// 	ImageID     string   `xml:"ImageID"`     // 图片ID
// 	ImageData   string   `xml:"ImageData"`   // 分片数据
// 	TotalChunks int      `xml:"TotalChunks"` // 总分片数
// 	ChunkIndex  int      `xml:"ChunkIndex"`  // 当前分片索引
// }
