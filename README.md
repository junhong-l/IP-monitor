# IP地址监控系统

一个用Go语言开发的IP地址监控系统，能够自动监控服务器的公网和私网IP地址变化，并在检测到变化时通过邮件通知管理员。

## ✨ 功能特点

- ✅ **全面监控**：支持公网IPv4/IPv6和私网IPv4/IPv6地址监控
- ✅ **智能检测**：仅在IP发生变化时发送通知
- ✅ **Web管理**：现代化响应式Web配置界面
- ✅ **多收件人**：支持同时向多个邮箱发送通知
- ✅ **单文件部署**：前端页面已嵌入可执行文件
- ✅ **SQLite存储**：使用纯Go实现的SQLite，无需CGO依赖
- ✅ **IP服务管理**：用户可自定义IP获取服务URL
- ✅ **服务统计**：记录每个服务的成功率、响应时间
- ✅ **智能重试**：IP获取失败自动切换服务
- ✅ **断网检测**：检测网络连接状态
- ✅ **完整日志**：操作日志和应用日志，支持自动清理
- ✅ **配置导出/导入**：支持AES加密的配置导出导入
- ✅ **优雅关闭**：支持信号处理，正确清理资源

## 🚀 快速开始

### 编译

```bash
# Linux/macOS
go build -buildvcs=false -ldflags="-s -w" -o email-notify .

# Windows交叉编译Linux
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -buildvcs=false -ldflags="-s -w" -o email-notify .
```

### 运行

```bash
# 添加执行权限(Linux/macOS)
chmod +x email-notify

# 运行
./email-notify -port 8543

# 访问Web界面
# http://localhost:8543
```

## 📧 邮件配置

Web界面内置了常用邮箱预设：

| 邮箱 | SMTP服务器 | 端口 | 说明 |
|------|-----------|------|------|
| QQ邮箱 | smtp.qq.com | 465/587 | 需使用授权码 |
| 163邮箱 | smtp.163.com | 465/587 | 需使用授权码 |
| Gmail | smtp.gmail.com | 587 | 需应用专用密码 |
| Outlook | smtp-mail.outlook.com | 587 | 使用账户密码 |

## 🛠️ 技术栈

- **语言**：Go 1.24+
- **数据库**：modernc.org/sqlite（纯Go实现的SQLite）
- **前端**：使用 `embed` 包嵌入到可执行文件
- **架构**：单文件部署，无外部依赖

## 📂 项目结构

```
email-notify/
├── main.go           # 主程序
├── database.go       # 数据库操作
├── email.go          # 邮件发送
├── ip_service.go     # IP服务管理
├── static/           # Web静态资源(嵌入)
└── go.mod            # Go模块依赖
```

## 🔧 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | 8543 | 服务监听端口 |

```bash
./email-notify -port 9000
```

## 🐛 故障排除

### 无法发送邮件
- 确认使用授权码而非账户密码
- 检查SMTP服务器和端口是否匹配
- 端口465用SSL，端口587用TLS

### 无法检测公网IP
- 确认服务器能访问外网
- 检查防火墙设置
- 在"IP服务管理"中测试服务可用性

## 飞牛NAS FPK 打包指南

### 目录结构

项目包含完整的FPK目录结构 `fnnas.ipnotify/`：  

<span style="color: red;">app/server 下面的文件名称要和cmd下面的脚本里面的应用名称一致</span>
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
### 步骤1：上传到飞牛NAS打包

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

### 步骤2：安装FPK

在飞牛NAS Web界面：
1. 进入"应用中心"
2. 点击"手动安装"
3. 上传 `fnnas.ipnotify.fpk` 文件
4. 按提示完成安装

```

