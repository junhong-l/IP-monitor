# IP地址监控邮件通知系统

这是一个用Go语言开发的IP地址监控系统，能够自动监控服务器的公网IP地址变化，并在检测到变化时通过邮件通知管理员。支持飞牛NAS（fnOS）FPK包安装。

## 功能特点

- ✅ **自动监控**：可设置监控间隔（5分钟~24小时）
- ✅ **智能检测**：仅在公网IP发生变化时发送通知
- ✅ **完整支持**：支持IPv4和IPv6地址检测（完整格式）
- ✅ **Web界面**：提供友好的Web配置界面
- ✅ **多收件人**：支持同时向多个邮箱发送通知
- ✅ **SMTP预设**：内置QQ、163、Gmail等常用邮箱配置
- ✅ **单文件部署**：前端页面已嵌入可执行文件
- ✅ **安全端口**：默认使用8543端口

---

## 快速开始

### 方式一：直接运行（开发/测试）

```bash
# 安装Go环境后，在项目目录运行
go run . -port 8543
```

### 方式二：编译后运行

参见下方"编译指南"章节。

### 访问Web界面

浏览器打开：`http://localhost:8543`

---

## 编译指南

### Windows 编译

```powershell
# 编译 Windows 可执行文件
go build -ldflags="-s -w" -o email-notify.exe .
```

### Linux 编译

```bash
# 在 Linux 系统上编译
go build -ldflags="-s -w" -o email-notify .
```

### Windows 交叉编译 Linux

```powershell
# PowerShell 中执行
$env:GOOS="linux"
$env:GOARCH="amd64"
$env:CGO_ENABLED="0"
go build -ldflags="-s -w" -o email-notify .
```

### 编译后运行

```bash
# Windows
.\email-notify.exe -port 8543

# Linux
chmod +x email-notify
./email-notify -port 8543
```

---

## 飞牛NAS FPK 打包指南

### 目录结构

项目包含完整的FPK目录结构 `fnnas.ipnotify/`：

```
fnnas.ipnotify/
├── manifest                    # 应用清单
├── config/
│   ├── privilege               # 权限配置
│   └── resource                # 资源配置
├── cmd/
│   ├── main                    # 主控脚本（启动/停止/状态）
│   ├── install_init            # 安装前回调
│   ├── install_callback        # 安装后回调
│   ├── uninstall_init          # 卸载前回调
│   ├── uninstall_callback      # 卸载后回调
│   ├── upgrade_init            # 升级前回调
│   ├── upgrade_callback        # 升级后回调
│   ├── config_init             # 配置前回调
│   └── config_callback         # 配置后回调
└── app/
    ├── server/
    │   └── email-notify        # Linux可执行文件（需编译）
    └── ui/
        └── config/
            └── entry.json      # 桌面入口配置
```

### 打包步骤

#### 步骤1：编译Linux可执行文件

在Windows PowerShell中：
```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
$env:CGO_ENABLED="0"
go build -ldflags="-s -w" -o "fnnas.ipnotify/app/server/email-notify" .
```

或在Linux中：
```bash
cd /path/to/email-notify
go build -ldflags="-s -w" -o "fnnas.ipnotify/app/server/email-notify" .
```

#### 步骤2：上传到飞牛NAS打包

1. 将整个 `fnnas.ipnotify` 目录上传到飞牛NAS
2. SSH登录飞牛NAS，执行：

```bash 
cd /path/to/fnnas.ipnotify

# 确保脚本有执行权限
chmod +x cmd/*
chmod +x app/server/email-notify

# 打包为fpk（fpk本质是tar.gz）
cd /path/to/fnnas.ipnotify  
fnpack build
```

#### 步骤3：安装FPK

在飞牛NAS Web界面：
1. 进入"应用中心"
2. 点击"手动安装"
3. 上传 `fnnas.ipnotify.fpk` 文件
4. 按提示完成安装

```

---

## 常用邮箱配置

Web界面内置了预设按钮，点击即可自动填充。

| 邮箱 | SMTP服务器 | 端口 | 说明 |
|------|-----------|------|------|
| QQ邮箱 | smtp.qq.com | 465/587 | 需使用授权码 |
| 163邮箱 | smtp.163.com | 465/587 | 需使用授权码 |
| Gmail | smtp.gmail.com | 587 | 需应用专用密码 |
| Outlook | smtp-mail.outlook.com | 587 | 使用账户密码 |
| 阿里企业邮 | smtp.qiye.aliyun.com | 465 | 使用账户密码 |

**端口说明**：
- `465`：SSL加密连接
- `587`：STARTTLS加密连接

---

## 项目结构

```
email-notify/
├── main.go              # 主程序（Web服务器、API、嵌入静态文件）
├── ip.go                # IP地址检测
├── email.go             # 邮件发送（SSL/TLS）
├── go.mod               # Go模块定义
├── static/
│   └── index.html       # Web界面（编译时嵌入）
├── config.json          # 运行时配置（自动生成）
├── fnnas.ipnotify/      # FPK打包目录
└── README.md
```

---

## 配置文件

运行时自动生成 `config.json`：

```json
{
  "sender_email": "your-email@example.com",
  "sender_password": "your-auth-code",
  "smtp_server": "smtp.example.com",
  "smtp_port": 587,
  "recipients": ["recipient@example.com"],
  "last_public_ips": ["123.45.67.89"],
  "auto_mode": true,
  "interval_minutes": 30
}
```

---

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | 8543 | 服务监听端口 |

```bash
./email-notify -port 9000
```

---

## 故障排除

### 无法发送邮件
- 确认使用授权码而非账户密码
- 检查SMTP服务器和端口是否匹配
- 端口465用SSL，端口587用TLS

### 无法检测公网IP
- 确认服务器能访问外网
- 检查防火墙是否阻止了ipify.org等服务

### FPK安装失败
- 确保 `cmd/*` 脚本有执行权限
- 检查脚本换行符为Unix格式（LF，不是CRLF）
- 查看飞牛系统日志

---

## 开发信息

- **语言**：Go 1.21+
- **依赖**：仅使用Go标准库（零外部依赖）
- **前端**：使用 `embed` 包嵌入到可执行文件

## 许可证

MIT License

## 更新日志

### v1.0.0 (2025-12-19)
- 初始版本
- IPv4/IPv6地址监控
- 邮件通知（SSL/TLS）
- Web配置界面
- 飞牛NAS FPK打包支持
