# 设置变量
IMAGE_NAME="1017496103/gb28181-app"
TAG="v0.3.0"

# 创建一个新的buildx builder实例，并设置为默认
docker buildx create --use --name multiarch-builder || true

# 构建多平台镜像
docker buildx build \
    --platform linux/amd64,linux/arm/v7,linux/arm64 \
    --tag $IMAGE_NAME:$TAG \
    --load \
    .
    # --push \ 暂时不推送
    


    

# 登录Docker Hub（如果需要）
# docker login

echo "Docker images built and pushed successfully!"