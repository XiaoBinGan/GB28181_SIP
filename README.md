# GB28181 SIP级联

+ 1.通讯协议UDP

+ 2.接入下级GB28181平台的服务

+ 3.获取下级平台的设备

+ 4.对接上级GB28181平台服务

+ 5.将下级平台的设备通过sip协议proxy给到上级平台

+ 6.接收上级平台的设备请求。

+ 7.接收上级平台的视频流点播请求

+ 8.将下级平台的真实的流转发给上级发出请求的平台




# build
```
./build/&push.sh
sudo docker build  -f Dockerfile -t sip .

```
run 

```
docker run -d -p 5060:5060 --name gb28181-container gb28181-app
```




linux build

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sipClient  main.go
```
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sipServer  main.go
```







## git config

```linux
git init

git add README.md

git commit -m "first commit"

git branch -M main

git remote add origin git@github.com:XiaoBinGan/GB28181_SIP.git

git push -u origin main

&&

git remote add origin git@github.com:XiaoBinGan/GB28181_SIP.git

git branch -M main

git push -u origin main
```
