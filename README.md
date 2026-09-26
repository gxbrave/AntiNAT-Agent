# AntiNAT Agent

[English](README.en.md)

AntiNAT Agent 是 AntiNAT 的独立数据面程序。它运行在目标网络里，负责监听本地服务、尝试 NAT 穿透和端口映射、转发 TCP/UDP 流量，并通过安全的控制通道接受主控配置。

主控项目在 [gxbrave/AntiNAT](https://github.com/gxbrave/AntiNAT)。主控负责管理节点、转发规则、认证和探测结果；Agent 不会把业务流量绕到主控上。

## 能做什么

- 接收主控下发的转发配置，并管理本地 TCP/UDP 监听和连接。
- 按配置尝试直连、STUN、PCP、NAT-PMP、UPnP 等映射/穿透路径。
- 保存节点身份、密钥、映射和恢复信息，重启后按持久化状态恢复。
- 通过签名控制帧和节点身份保护注册、心跳、配置同步和状态回报。
- 支持 Linux 服务安装，以及 Docker 相关的状态和注册辅助脚本。

## 开始使用

### 环境要求

- Linux amd64（当前最完整的运行目标）
- Go 1.26.6，或与 CI 兼容的 Go 版本
- 自行编译需要 Go 和常用 Unix 工具；服务安装需要 root 权限

### 方式一：使用主控生成的安装命令

先在主控中添加 Agent，再复制主控生成的安装命令到目标 Linux 主机执行。命令调用本仓库根目录的 [`install.sh`](install.sh)，入口地址为 `https://raw.githubusercontent.com/gxbrave/AntiNAT-Agent/main/install.sh`。

入口没有菜单，也不支持脱离主控的无参数安装。主控必须提供节点 ID（`ANTINAT_NODE_ID`）、公钥 pin（`ANTINAT_CONTROLLER_PIN`）和地址（`--controller-endpoint`）。一次性注册 token 默认在终端隐藏输入，自动化使用 `--token-file`（0600 文件）或 `--token-fd`，不要将 token 明文放入命令行。

选择主控的一键安装菜单“主控 + Agent”时，主控会自动创建本地 Agent，并使用 `http://127.0.0.1:用户设定端口` 安装注册。Docker 主控由用户通过镜像部署，Agent 仍需单独使用主控生成的命令安装。

入口默认下载本仓库已发布的 `v1.0.0-beta.3` Release 安装器、信任根和签名制品。可通过 `ANTINAT_AGENT_RELEASE_VERSION` 选择版本，或通过 `ANTINAT_AGENT_RELEASE_BASE_URL` 指定 HTTPS Release 镜像前缀；不会继承主控的 Release 下载地址。底层参数与安全约束见 [`docs/installer-contract.md`](docs/installer-contract.md)。

### 方式二：自行编译

```bash
git clone https://github.com/gxbrave/AntiNAT-Agent.git
cd AntiNAT-Agent

# 跑测试和静态检查
GOWORK=off make check

# 编译 Agent
GOWORK=off make build

# 查看版本
./bin/antinat-agent version
```

先在主控里创建节点并获取一次性注册 token、节点 ID 和主控公钥 pin，再启动 Agent：

```bash
chmod 600 ./var/enrollment.token
./bin/antinat-agent \
  --endpoint https://你的主控地址 \
  --node <节点 ID> \
  --token-file ./var/enrollment.token \
  --pin <64 位十六进制主控公钥> \
  --state ./var/agent
```

成功注册后，Agent 会消费一次性 token。已有本地注册状态时，可以省略 `--token-file` 和 `--pin`：

```bash
./bin/antinat-agent \
  --endpoint https://你的主控地址 \
  --node <节点 ID> \
  --state ./var/agent
```

也可以使用 `ANTINAT_ENDPOINT`、`ANTINAT_NODE`、`ANTINAT_TOKEN_FILE`、`ANTINAT_PIN` 和 `ANTINAT_STATE` 环境变量。

### 常用选项

- `--stun-servers`：逗号分隔的 `stun+tcp://` 服务地址。
- `--auto-order`：明确指定自动策略顺序，例如 `explicit-gateway,direct-v4,stun-only`。
- `--token-fd`：从受保护的文件描述符读取 token，适合自动化部署。
- `--state`：本地状态目录，默认是 `./var/agent`。

## 支持范围

当前发布版本为 `v1.0.0-beta.3`，状态是 `SUPPORTED_WITH_LIMITS`：

- Linux amd64 的构建、单元测试、竞态测试和本地协议测试较完整。
- Windows amd64 主要有交叉编译和安装器编译检查，不宣称完整 Windows 运行时支持。
- Linux arm64、OpenRC、真实公网 WAN/CPE 路由器和长时间运行证据还不完整。
- Agent 不能保证任意 NAT 都能打通；IPv6 目前只用于控制通道，转发数据面仍是 IPv4 范围。

## 目录说明

- `internal/agent`：注册、控制会话、本地状态、恢复和生命周期。
- `internal/forward`：TCP/UDP 转发。
- `internal/traversal`：直连、STUN、PCP、NAT-PMP 和 UPnP 策略。
- `internal/protocol`：签名控制帧和探测帧。
- `internal/security`：节点密钥、轮换和帧保护。
- `deploy/`、`docker/`：服务文件、容器和注册辅助脚本。
- `docs/nat-support.md`：NAT 能力和限制说明。

## 实现方式

Agent 是数据面的唯一归属方：主控只下发期望状态和探测任务，Agent 在本地完成监听、映射、穿透、目标连接和流量转发。控制会话使用节点身份和签名协议帧，配置变化先进入本地持久化协调器，再按顺序执行，避免重启或网络抖动时丢失状态。

每个转发都有稳定 ID 和独立的激活代次。普通目标更新只影响新连接，删除才是明确的立即停止操作。探测结果与本地监听、STUN 地址分开保存；只有经过认证的独立探测，才可以把候选地址提升为可发布结果。

安装器把 Release manifest 当作信任边界：下载后先校验签名和 SHA-256，再复制二进制、写服务和记录所有权清单。token 只在注册流程中短暂使用，不进入 argv、服务文件或普通日志。

## 测试

```bash
python3 -m unittest discover -s tests
bash -n install.sh
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
GOWORK=off make cross-build
```

完整限制和测试证据见 [`docs/support-matrix.md`](docs/support-matrix.md)。

## 许可证

本项目采用 [GPL-3.0](LICENSE) 发布。
