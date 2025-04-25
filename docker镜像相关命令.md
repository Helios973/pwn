### 镜像相关命令

- **docker images** ：列出本地镜像。例如，`docker images` 可以列出所有本地镜像的详细信息，包括镜像 ID、仓库名称、标签、创建时间以及大小等。
- **docker pull** ：从镜像仓库拉取镜像。例如，`docker pull nginx` 会从 Docker Hub 仓库拉取最新的 nginx 镜像。
- **docker rmi** ：删除本地镜像。例如，`docker rmi nginx` 可以删除本地的 nginx 镜像，不过如果该镜像正被容器使用，则需要先停止并删除相关容器才能删除成功。

### 容器相关命令

- **docker ps** ：列出正在运行的容器。例如，`docker ps` 可以查看当前所有处于运行状态的容器的信息，包括容器 ID、镜像名称、命令、创建时间、状态、端口映射等。使用`docker ps -a` 可以查看所有状态（包括已停止）的容器。
- **docker run** ：创建并启动一个新的容器。例如，`docker run -d -p 8080:80 nginx` 表示以后台模式（-d 参数）运行 nginx 容器，并将主机的 8080 端口映射到容器的 80 端口。
- **docker start/stop/restart** ：启动、停止和重启容器。例如，`docker start container_id` 可以启动指定 ID 的容器，`docker stop container_id` 可以停止容器，`docker restart container_id` 则是重启容器。
- **docker rm** ：删除容器。例如，`docker rm container_id` 可以删除指定的已停止的容器。如果要强制删除正在运行的容器，可以使用`docker rm -f container_id`。

### 数据卷相关命令

- **docker volume create** ：创建一个新的数据卷。例如，`docker volume create my_volume` 可以创建一个名为 my_volume 的数据卷，用于在容器和主机之间持久化数据。
- **docker volume ls** ：列出所有数据卷。例如，`docker volume ls` 可以查看当前系统中存在的所有数据卷的名称和驱动类型等信息。
- **docker volume rm** ：删除数据卷。例如，`docker volume rm my_volume` 可以删除名为 my_volume 的数据卷，但只有在该数据卷未被任何容器使用时才能成功删除。

### 网络相关命令

- **docker network ls** ：列出所有 Docker 网络。例如，`docker network ls` 可以查看当前系统中存在的所有 Docker 网络的 ID、名称、驱动等信息。
- **docker network create** ：创建一个新的网络。例如，`docker network create my_network` 可以创建一个自定义的桥接网络 my_network，方便容器之间的通信。
- **docker network inspect** ：查看网络的详细信息。例如，`docker network inspect my_network` 可以获取 my_network 网络的详细配置信息，如子网、网关、IPAM 配置等。
- **docker network rm** ：删除网络。例如，`docker network rm my_network` 可以删除指定的网络 my_network，但前提是该网络中没有正在运行的容器。

### 其他命令

- **docker exec** ：在运行中的容器内执行命令。例如，`docker exec -it container_id /bin/bash` 可以进入指定容器的 bash shell，方便在容器内部进行操作和调试。
- **docker logs** ：查看容器的日志。例如，`docker logs container_id` 可以查看容器的标准输出和标准错误日志，这对于排查容器应用的问题非常有帮助。
- **docker stats** ：实时查看容器的资源使用情况。例如，`docker stats` 可以显示各个容器的 CPU、内存、网络和磁盘 I/O 等资源的使用统计信息，有助于监控容器的性能。
- **docker info** ：显示 Docker 系统的详细信息。例如，`docker info` 可以查看 Docker 的版本、系统配置、镜像和容器的数量等信息。
