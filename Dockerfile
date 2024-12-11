# 使用官方Golang镜像作为构建环境
FROM golang:1.21.3 AS builder

# 设置工作目录
WORKDIR /app

# 将go.mod和go.sum复制到容器中并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 将所有源代码复制到容器中
COPY . .

# 构建应用程序，指定目标平台
# RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gb28181-app ./main.go
RUN go build -o gb28181-app ./main.go

# 使用轻量级的基础镜像来运行应用
FROM alpine:latest

# 设置工作目录
WORKDIR /root/

# 从构建阶段复制可执行文件到此阶段
COPY --from=builder /app/gb28181-app .


# 赋予可执行文件权限
RUN chmod +x gb28181-app

# 复制配置文件和其他必要的资源文件
COPY conf/ /root/conf/
COPY logs/ /root/logs/

# 暴露服务监听端口（根据实际情况修改  如果作为服务端则是5061 作为客户端则为5060）
EXPOSE 5060 

# 运行应用程序
CMD ["./gb28181-app"]