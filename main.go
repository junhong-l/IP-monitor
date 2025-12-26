package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

var (
	port   = flag.Int("port", 8543, "服务监听端口（默认8543）")
	dbFile = "data.db"
)

var (
	monitorTicker *time.Ticker
	monitorStop   chan bool
	monitorMu     sync.Mutex

	logCleanupStop chan bool
)

func main() {
	flag.Parse()

	// 初始化数据库
	if err := InitDatabase(dbFile); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer CloseDatabase()

	// 初始化默认配置(首次运行时)
	if err := InitDefaultConfig(); err != nil {
		log.Fatalf("初始化默认配置失败: %v", err)
	}

	DBLogInfo("IP地址监控系统启动")

	// 读取监控配置
	monitorCfg, err := GetMonitorConfig()
	if err != nil {
		log.Fatalf("读取监控配置失败: %v", err)
	}

	// 启动日志清理定时任务（每小时清理一次）
	retentionHours := monitorCfg.LogRetentionHours
	if retentionHours <= 0 {
		retentionHours = 72 // 默认保留72小时（3天）
	}
	logCleanupStop = make(chan bool)
	StartLogCleanupScheduler(retentionHours)

	// 启动时立即检查一次IP变化（无论是否启用自动监控）
	DBLogInfo("程序启动，开始检查IP地址...")
	checkAndNotifyIPChange()

	// 根据配置启动IP监控
	if monitorCfg.AutoMode {
		startIPMonitor()
	}

	// 启动Web服务器
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/static/", handleStatic)
	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/config/email", handleSaveEmailConfig)
	http.HandleFunc("/api/config/monitor", handleSaveMonitorConfig)
	http.HandleFunc("/api/ips", handleGetIPs)
	http.HandleFunc("/api/test-email", handleTestEmail)
	http.HandleFunc("/api/check-ip", handleCheckIP)
	http.HandleFunc("/api/monitor/status", handleMonitorStatus)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/logs/app", handleAppLogs)
	http.HandleFunc("/api/logs/config", handleLogConfig)
	http.HandleFunc("/api/logs/clean", handleCleanLogs)
	// IP服务管理API
	http.HandleFunc("/api/ip-services", handleIPServices)
	http.HandleFunc("/api/ip-services/get", handleGetIPServiceByID)
	http.HandleFunc("/api/ip-services/test", handleTestIPService)
	http.HandleFunc("/api/ip-services/add", handleAddIPService)
	http.HandleFunc("/api/ip-services/update", handleUpdateIPService)
	http.HandleFunc("/api/ip-services/delete", handleDeleteIPService)
	// 导入导出API
	http.HandleFunc("/api/export", handleExport)
	http.HandleFunc("/api/import", handleImport)

	addr := fmt.Sprintf(":%d", *port)
	DBLogInfo("服务器启动在端口 %d", *port)

	// 设置信号处理器,优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		DBLogInfo("接收到关闭信号,正在停止服务...")
		StopLogCleanupScheduler()
		CloseDatabase()
		os.Exit(0)
	}()

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("启动服务器失败:", err)
	}
}

func startIPMonitor() {
	monitorMu.Lock()
	defer monitorMu.Unlock()

	// 如果已经在运行，先停止
	if monitorTicker != nil {
		monitorTicker.Stop()
		if monitorStop != nil {
			close(monitorStop)
		}
	}

	// 从数据库读取监控配置
	monitorCfg, err := GetMonitorConfig()
	if err != nil {
		DBLogError("读取监控配置失败: %v", err)
		return
	}

	interval := time.Duration(monitorCfg.IntervalMinutes) * time.Minute
	monitorTicker = time.NewTicker(interval)
	monitorStop = make(chan bool)

	DBLogInfo("启动自动监控，间隔: %d 分钟", monitorCfg.IntervalMinutes)

	// 在锁保护内启动goroutine,确保monitorStop在goroutine启动前不会被关闭
	go func() {
		for {
			select {
			case <-monitorTicker.C:
				checkAndNotifyIPChange()
			case <-monitorStop:
				DBLogInfo("停止自动监控")
				return
			}
		}
	}()

	// Unlock在defer中执行,goroutine已经安全启动
}

func stopIPMonitor() {
	monitorMu.Lock()
	defer monitorMu.Unlock()

	if monitorTicker != nil {
		monitorTicker.Stop()
		monitorTicker = nil
	}
	if monitorStop != nil {
		// 安全关闭channel:使用select避免向已关闭channel发送
		select {
		case <-monitorStop:
			// channel已关闭
		default:
			close(monitorStop)
		}
		monitorStop = nil
	}
	DBLogInfo("自动监控已停止")
}

func restartIPMonitor() {
	stopIPMonitor()
	monitorCfg, err := GetMonitorConfig()
	if err == nil && monitorCfg.AutoMode {
		startIPMonitor()
	}
}

func checkAndNotifyIPChange() {
	DBLogInfo("开始检查IP地址...")

	// 使用新的IP获取逻辑
	ipv4, ipv6, networkOK := GetAllPublicIPs()

	// 获取本地私网IP
	privateIPv4, privateIPv6 := GetLocalIPs()

	currentIPs := IPInfo{
		PublicIPv4:  []string{},
		PublicIPv6:  []string{},
		PrivateIPv4: privateIPv4,
		PrivateIPv6: privateIPv6,
	}

	if ipv4 != "" && ipv4 != DisconnectedIPv4 {
		currentIPs.PublicIPv4 = []string{ipv4}
	}
	if ipv6 != "" && ipv6 != DisconnectedIPv6 {
		currentIPs.PublicIPv6 = []string{ipv6}
	}

	// 从数据库读取上次的IP（根据监控类型）
	lastIPs, err := GetAllLastIPs()
	if err != nil {
		DBLogError("读取上次IP失败: %v", err)
		return
	}

	// 打印历史IP
	if len(lastIPs) > 0 {
		DBLogInfo("历史IP地址:")
		if ips, ok := lastIPs["public_ipv4"]; ok && len(ips) > 0 {
			DBLogInfo("  公网IPv4: %v", ips)
		}
		if ips, ok := lastIPs["public_ipv6"]; ok && len(ips) > 0 {
			DBLogInfo("  公网IPv6: %v", ips)
		}
		if ips, ok := lastIPs["private_ipv4"]; ok && len(ips) > 0 {
			DBLogInfo("  私网IPv4: %v", ips)
		}
		if ips, ok := lastIPs["private_ipv6"]; ok && len(ips) > 0 {
			DBLogInfo("  私网IPv6: %v", ips)
		}
	}

	// 打印当前IP
	DBLogInfo("当前IP地址:")
	if len(currentIPs.PublicIPv4) > 0 {
		DBLogInfo("  公网IPv4: %v", currentIPs.PublicIPv4)
	} else {
		DBLogInfo("  公网IPv4: (未获取)")
	}
	if len(currentIPs.PublicIPv6) > 0 {
		DBLogInfo("  公网IPv6: %v", currentIPs.PublicIPv6)
	} else {
		DBLogInfo("  公网IPv6: (未获取)")
	}
	if len(currentIPs.PrivateIPv4) > 0 {
		DBLogInfo("  私网IPv4: %v", currentIPs.PrivateIPv4)
	}
	if len(currentIPs.PrivateIPv6) > 0 {
		DBLogInfo("  私网IPv6: %v", currentIPs.PrivateIPv6)
	}

	// 构建上次的IPInfo（根据监控配置读取对应类型的IP）
	oldIPs := IPInfo{}

	// 根据监控类型从数据库读取公网IP
	if shouldMonitor("public_ipv4") {
		if ips, ok := lastIPs["public_ipv4"]; ok && len(ips) > 0 {
			oldIPs.PublicIPv4 = ips
		}
	}
	if shouldMonitor("public_ipv6") {
		if ips, ok := lastIPs["public_ipv6"]; ok && len(ips) > 0 {
			oldIPs.PublicIPv6 = ips
		}
	}

	// 私网IP根据监控配置读取（避免未监控时触发误报）
	if shouldMonitor("private_ipv4") {
		if ips, ok := lastIPs["private_ipv4"]; ok && len(ips) > 0 {
			oldIPs.PrivateIPv4 = ips
		}
	}
	if shouldMonitor("private_ipv6") {
		if ips, ok := lastIPs["private_ipv6"]; ok && len(ips) > 0 {
			oldIPs.PrivateIPv6 = ips
		}
	}

	// 检查是否首次运行（数据库中没有任何上次IP记录）
	// 注意：这里只检查公网IP，因为私网IP可能在首次运行时就有
	isFirstRun := len(lastIPs) == 0 ||
		(len(oldIPs.PublicIPv4) == 0 && len(oldIPs.PublicIPv6) == 0)

	if isFirstRun {
		DBLogInfo("首次运行，记录当前IP地址到数据库（不发送通知）")

		// 保存当前IP到数据库
		// 首次运行时总是保存所有IP(公网+私网),不管监控配置如何
		// 这样邮件中可以显示完整的IP信息
		if len(currentIPs.PublicIPv4) > 0 {
			SaveLastIPs("public_ipv4", currentIPs.PublicIPv4)
		}
		if len(currentIPs.PublicIPv6) > 0 {
			SaveLastIPs("public_ipv6", currentIPs.PublicIPv6)
		}
		if len(currentIPs.PrivateIPv4) > 0 {
			SaveLastIPs("private_ipv4", currentIPs.PrivateIPv4)
		}
		if len(currentIPs.PrivateIPv6) > 0 {
			SaveLastIPs("private_ipv6", currentIPs.PrivateIPv6)
		}

		return
	}

	// 处理断网情况
	if !networkOK {
		DBLogWarn("网络断开，IP地址设为占位符，等待网络恢复")

		// 断网时保存占位符IP（仅保存监控的类型）
		if shouldMonitor("public_ipv4") {
			SaveLastIPs("public_ipv4", []string{DisconnectedIPv4})
		}
		if shouldMonitor("public_ipv6") {
			SaveLastIPs("public_ipv6", []string{DisconnectedIPv6})
		}

		return
	}

	// 比较IP变化（根据监控类型）
	changes := compareAllIPs(&oldIPs, &currentIPs)

	// 处理公网IPv4/IPv6获取失败的情况（仅检查监控的类型）
	if shouldMonitor("public_ipv4") && shouldMonitor("public_ipv6") {
		oldIPv4 := ""
		oldIPv6 := ""
		if ips, ok := lastIPs["public_ipv4"]; ok && len(ips) > 0 {
			oldIPv4 = ips[0]
		}
		if ips, ok := lastIPs["public_ipv6"]; ok && len(ips) > 0 {
			oldIPv6 = ips[0]
		}

		ipv4Failed := ipv4 == "" && oldIPv4 != "" && oldIPv4 != DisconnectedIPv4
		ipv6Failed := ipv6 == "" && oldIPv6 != "" && oldIPv6 != DisconnectedIPv6

		if (ipv4Failed && ipv6 != "") || (ipv6Failed && ipv4 != "") {
			// 一个有值一个为空，检查网络连通性
			netOK, _ := CheckNetworkConnectivity()
			if netOK {
				// 网络正常但获取失败，可能是服务问题，发送警告邮件
				var warningType string
				if ipv4Failed {
					warningType = "IPv4"
					DBLogWarn("IPv4获取失败但网络正常，之前IP: %s，可能需要更换IP获取服务", oldIPv4)
				} else {
					warningType = "IPv6"
					DBLogWarn("IPv6获取失败但网络正常，之前IP: %s，可能需要更换IP获取服务", oldIPv6)
				}

				// 发送警告邮件
				emailCfg, _ := GetEmailConfig()
				if emailCfg.SenderEmail == "" || emailCfg.SenderPassword == "" || len(emailCfg.Recipients) == 0 {
					DBLogWarn("邮件配置不完整，无法发送警告邮件（发件人、密码或收件人为空）")
				} else {
					err := sendIPFetchWarningEmail(warningType, oldIPv4, oldIPv6, ipv4, ipv6)
					if err != nil {
						DBLogError("发送警告邮件失败: %v", err)
					} else {
						DBLogInfo("警告邮件发送成功，收件人: %v", emailCfg.Recipients)
					}
				}
			}
		}
	}

	// 如果有变化，发送通知并更新数据库
	if len(changes) > 0 {
		// 记录详细的IP变化
		for _, change := range changes {
			if len(change.Added) > 0 {
				DBLogInfo("IP变化 [%s] 新增: %v", change.Type, change.Added)
			}
			if len(change.Removed) > 0 {
				DBLogInfo("IP变化 [%s] 移除: %v", change.Type, change.Removed)
			}
		}

		// 发送通知邮件
		emailCfg, _ := GetEmailConfig()
		if emailCfg.SenderEmail == "" || emailCfg.SenderPassword == "" || len(emailCfg.Recipients) == 0 {
			DBLogWarn("邮件配置不完整，无法发送IP变化通知（发件人、密码或收件人为空）")
		} else {
			err := sendAllIPChangeNotification(&oldIPs, &currentIPs, changes)
			if err != nil {
				DBLogError("发送邮件失败: %v", err)
			} else {
				DBLogInfo("邮件通知发送成功，收件人: %v", emailCfg.Recipients)
			}
		}
	} else {
		DBLogInfo("所有监控的IP地址无变化")
	}

	// 无论是否有变化，都更新数据库中的最后IP（仅保存监控的类型）
	if networkOK {
		if shouldMonitor("public_ipv4") && len(currentIPs.PublicIPv4) > 0 {
			SaveLastIPs("public_ipv4", currentIPs.PublicIPv4)
		}
		if shouldMonitor("public_ipv6") && len(currentIPs.PublicIPv6) > 0 {
			SaveLastIPs("public_ipv6", currentIPs.PublicIPv6)
		}
		if shouldMonitor("private_ipv4") && len(currentIPs.PrivateIPv4) > 0 {
			SaveLastIPs("private_ipv4", currentIPs.PrivateIPv4)
		}
		if shouldMonitor("private_ipv6") && len(currentIPs.PrivateIPv6) > 0 {
			SaveLastIPs("private_ipv6", currentIPs.PrivateIPv6)
		}
	}
}

func hasIPChanged(oldIPs, newIPs []string) bool {
	if len(oldIPs) != len(newIPs) {
		return true
	}
	
	oldMap := make(map[string]bool)
	for _, ip := range oldIPs {
		oldMap[ip] = true
	}
	
	for _, ip := range newIPs {
		if !oldMap[ip] {
			return true
		}
	}
	
	return false
}

// IPChange 表示IP变化信息
type IPChange struct {
	Type    string   `json:"type"`    // 类型: public_ipv4, public_ipv6, private_ipv4, private_ipv6
	Added   []string `json:"added"`   // 新增的IP
	Removed []string `json:"removed"` // 移除的IP
}

// 检查是否监控某种IP类型
func shouldMonitor(ipType string) bool {
	monitorCfg, err := GetMonitorConfig()
	if err != nil {
		DBLogError("读取监控配置失败: %v", err)
		return false
	}

	for _, t := range monitorCfg.MonitorTypes {
		if t == ipType {
			return true
		}
	}
	return false
}

// 获取当前邮件配置(辅助函数,避免重复代码)
func getCurrentEmailConfig() *EmailConfig {
	cfg, err := GetEmailConfig()
	if err != nil {
		return &EmailConfig{}
	}
	return cfg
}

// 获取当前监控配置(辅助函数,避免重复代码)
func getCurrentMonitorConfig() *MonitorConfig {
	cfg, err := GetMonitorConfig()
	if err != nil {
		return &MonitorConfig{
			IntervalMinutes:   30,
			MonitorTypes:      []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"},
			LogRetentionHours: 72,
		}
	}
	return cfg
}

// 比较所有IP，返回变化列表（根据监控类型过滤）
func compareAllIPs(oldIPs, newIPs *IPInfo) []IPChange {
	var changes []IPChange

	// 比较公网IPv4（根据监控配置）
	if shouldMonitor("public_ipv4") {
		if added, removed := compareIPList(oldIPs.PublicIPv4, newIPs.PublicIPv4); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "公网IPv4", Added: added, Removed: removed})
		}
	}

	// 比较公网IPv6（根据监控配置）
	if shouldMonitor("public_ipv6") {
		if added, removed := compareIPList(oldIPs.PublicIPv6, newIPs.PublicIPv6); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "公网IPv6", Added: added, Removed: removed})
		}
	}

	// 比较私网IPv4（根据监控配置）
	if shouldMonitor("private_ipv4") {
		if added, removed := compareIPList(oldIPs.PrivateIPv4, newIPs.PrivateIPv4); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "私网IPv4", Added: added, Removed: removed})
		}
	}

	// 比较私网IPv6（根据监控配置）
	if shouldMonitor("private_ipv6") {
		if added, removed := compareIPList(oldIPs.PrivateIPv6, newIPs.PrivateIPv6); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "私网IPv6", Added: added, Removed: removed})
		}
	}

	return changes
}

// 比较两个IP列表，返回新增和移除的IP
func compareIPList(oldList, newList []string) (added, removed []string) {
	oldMap := make(map[string]bool)
	newMap := make(map[string]bool)
	
	for _, ip := range oldList {
		oldMap[ip] = true
	}
	for _, ip := range newList {
		newMap[ip] = true
	}
	
	// 找出新增的
	for _, ip := range newList {
		if !oldMap[ip] {
			added = append(added, ip)
		}
	}
	
	// 找出移除的
	for _, ip := range oldList {
		if !newMap[ip] {
			removed = append(removed, ip)
		}
	}
	
	return
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	// 从嵌入的文件系统读取index.html
	content, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "页面未找到", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

// 静态文件服务（用于CSS、JS等其他静态资源）
func handleStatic(w http.ResponseWriter, r *http.Request) {
	// 从嵌入的文件系统提供静态文件
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		http.Error(w, "资源未找到", http.StatusNotFound)
		return
	}
	http.StripPrefix("/static/", http.FileServer(http.FS(subFS))).ServeHTTP(w, r)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	// 从数据库读取配置
	emailCfg, _ := GetEmailConfig()
	monitorCfg, _ := GetMonitorConfig()

	// 不返回密码
	safeConfig := struct {
		SenderEmail     string   `json:"sender_email"`
		SMTPServer      string   `json:"smtp_server"`
		SMTPPort        int      `json:"smtp_port"`
		Recipients      []string `json:"recipients"`
		AutoMode        bool     `json:"auto_mode"`
		IntervalMinutes int      `json:"interval_minutes"`
	}{
		SenderEmail:     emailCfg.SenderEmail,
		SMTPServer:      emailCfg.SMTPServer,
		SMTPPort:        emailCfg.SMTPPort,
		Recipients:      emailCfg.Recipients,
		AutoMode:        monitorCfg.AutoMode,
		IntervalMinutes: monitorCfg.IntervalMinutes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(safeConfig)
}

// 保存邮件配置(独立模块)
func handleSaveEmailConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var emailConfig struct {
		SenderEmail    string   `json:"sender_email"`
		SenderPassword string   `json:"sender_password"`
		SMTPServer     string   `json:"smtp_server"`
		SMTPPort       int      `json:"smtp_port"`
		Recipients     []string `json:"recipients"`
	}

	if err := json.NewDecoder(r.Body).Decode(&emailConfig); err != nil {
		http.Error(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	// 获取当前配置
	currentCfg, _ := GetEmailConfig()

	// 只更新非空字段
	if emailConfig.SenderEmail != "" {
		currentCfg.SenderEmail = emailConfig.SenderEmail
	}
	if emailConfig.SenderPassword != "" {
		currentCfg.SenderPassword = emailConfig.SenderPassword
	}
	if emailConfig.SMTPServer != "" {
		currentCfg.SMTPServer = emailConfig.SMTPServer
	}
	if emailConfig.SMTPPort > 0 {
		currentCfg.SMTPPort = emailConfig.SMTPPort
	}
	if emailConfig.Recipients != nil {
		currentCfg.Recipients = emailConfig.Recipients
	}

	// 保存到数据库
	if err := SaveEmailConfig(currentCfg); err != nil {
		DBLogError("保存邮件配置失败: %v", err)
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	DBLogInfo("用户保存邮件配置成功: 发件人=%s, SMTP=%s:%d, 收件人=%v",
		currentCfg.SenderEmail, currentCfg.SMTPServer, currentCfg.SMTPPort, currentCfg.Recipients)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// 保存监控配置(独立模块)
func handleSaveMonitorConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var monitorConfig struct {
		AutoMode        bool     `json:"auto_mode"`
		IntervalMinutes int      `json:"interval_minutes"`
		MonitorTypes    []string `json:"monitor_types"`
	}

	if err := json.NewDecoder(r.Body).Decode(&monitorConfig); err != nil {
		http.Error(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	// 获取当前配置
	currentCfg, _ := GetMonitorConfig()

	// 检查是否需要重启监控
	needRestart := currentCfg.AutoMode != monitorConfig.AutoMode ||
		currentCfg.IntervalMinutes != monitorConfig.IntervalMinutes

	// 更新配置
	currentCfg.AutoMode = monitorConfig.AutoMode
	if monitorConfig.IntervalMinutes > 0 {
		currentCfg.IntervalMinutes = monitorConfig.IntervalMinutes
	}
	if monitorConfig.MonitorTypes != nil {
		currentCfg.MonitorTypes = monitorConfig.MonitorTypes
	}

	// 保存到数据库
	if err := SaveMonitorConfig(currentCfg); err != nil {
		DBLogError("保存监控配置失败: %v", err)
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	modeStr := "手动"
	if currentCfg.AutoMode {
		modeStr = fmt.Sprintf("自动(每%d分钟)", currentCfg.IntervalMinutes)
	}
	DBLogInfo("用户保存监控配置成功: 模式=%s, 监控类型=%v", modeStr, currentCfg.MonitorTypes)

	// 如果监控配置变化，重启监控
	if needRestart {
		go restartIPMonitor()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func handleGetIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	allIPs := getAllIPs()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allIPs)
}

func handleTestEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	emailCfg := getCurrentEmailConfig()
	if emailCfg.SenderEmail == "" || len(emailCfg.Recipients) == 0 {
		http.Error(w, "请先配置发件人和收件人", http.StatusBadRequest)
		return
	}

	DBLogInfo("用户发送测试邮件到: %v", emailCfg.Recipients)

	err := sendTestEmail()
	if err != nil {
		DBLogError("测试邮件发送失败: %v", err)
		http.Error(w, fmt.Sprintf("发送测试邮件失败: %v", err), http.StatusInternalServerError)
		return
	}

	DBLogInfo("测试邮件发送成功")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "测试邮件发送成功"})
}

// 手动检查IP变化
func handleCheckIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	DBLogInfo("用户手动触发IP检查")

	// 使用新的IP获取逻辑
	ipv4, ipv6, networkOK := GetAllPublicIPs()
	privateIPv4, privateIPv6 := GetLocalIPs()

	currentIPs := IPInfo{
		PublicIPv4:  []string{},
		PublicIPv6:  []string{},
		PrivateIPv4: privateIPv4,
		PrivateIPv6: privateIPv6,
	}

	if ipv4 != "" && ipv4 != DisconnectedIPv4 {
		currentIPs.PublicIPv4 = []string{ipv4}
	}
	if ipv6 != "" && ipv6 != DisconnectedIPv6 {
		currentIPs.PublicIPv6 = []string{ipv6}
	}

	// 从数据库读取上次的IP
	lastIPs, err := GetAllLastIPs()
	if err != nil {
		DBLogError("读取上次IP失败: %v", err)
		http.Error(w, fmt.Sprintf("读取上次IP失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 构建上次的IPInfo（根据监控配置读取对应类型的IP）
	oldIPs := IPInfo{}

	// 根据监控类型从数据库读取公网IP
	if shouldMonitor("public_ipv4") {
		if ips, ok := lastIPs["public_ipv4"]; ok && len(ips) > 0 {
			oldIPs.PublicIPv4 = ips
		}
	}
	if shouldMonitor("public_ipv6") {
		if ips, ok := lastIPs["public_ipv6"]; ok && len(ips) > 0 {
			oldIPs.PublicIPv6 = ips
		}
	}

	// 私网IP根据监控配置读取（避免未监控时触发误报）
	if shouldMonitor("private_ipv4") {
		if ips, ok := lastIPs["private_ipv4"]; ok && len(ips) > 0 {
			oldIPs.PrivateIPv4 = ips
		}
	}
	if shouldMonitor("private_ipv6") {
		if ips, ok := lastIPs["private_ipv6"]; ok && len(ips) > 0 {
			oldIPs.PrivateIPv6 = ips
		}
	}

	// 检查是否首次运行
	// 注意：这里只检查公网IP，因为私网IP可能在首次运行时就有
	isFirstRun := len(lastIPs) == 0 ||
		(len(oldIPs.PublicIPv4) == 0 && len(oldIPs.PublicIPv6) == 0)

	result := struct {
		Changed    bool       `json:"changed"`
		Changes    []IPChange `json:"changes"`
		CurrentIPs *IPInfo    `json:"current_ips"`
		EmailSent  bool       `json:"email_sent"`
		Message    string     `json:"message"`
		NetworkOK  bool       `json:"network_ok"`
	}{
		Changed:    false,
		Changes:    []IPChange{},
		CurrentIPs: &currentIPs,
		EmailSent:  false,
		Message:    "所有监控的IP地址无变化",
		NetworkOK:  networkOK,
	}

	if isFirstRun {
		result.Message = "首次记录IP地址完成，后续变化将会通知"

		// 保存当前IP到数据库
		// 首次运行时总是保存所有IP(公网+私网),不管监控配置如何
		if networkOK {
			if len(currentIPs.PublicIPv4) > 0 {
				SaveLastIPs("public_ipv4", currentIPs.PublicIPv4)
			}
			if len(currentIPs.PublicIPv6) > 0 {
				SaveLastIPs("public_ipv6", currentIPs.PublicIPv6)
			}
			if len(currentIPs.PrivateIPv4) > 0 {
				SaveLastIPs("private_ipv4", currentIPs.PrivateIPv4)
			}
			if len(currentIPs.PrivateIPv6) > 0 {
				SaveLastIPs("private_ipv6", currentIPs.PrivateIPv6)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	if !networkOK {
		result.Message = "网络断开，无法获取公网IP"
	} else {
		// 比较IP变化
		changes := compareAllIPs(&oldIPs, &currentIPs)
		changed := len(changes) > 0

		result.Changes = changes
		result.Changed = changed

		if changed {
			result.Message = "检测到IP地址变化"

			// 发送通知邮件
			emailCfg := getCurrentEmailConfig()
			if emailCfg.SenderEmail != "" && len(emailCfg.Recipients) > 0 {
				err := sendAllIPChangeNotification(&oldIPs, &currentIPs, changes)
				if err != nil {
					result.Message = fmt.Sprintf("IP变化已检测，但邮件发送失败: %v", err)
				} else {
					result.EmailSent = true
					result.Message = "IP变化已检测，邮件通知已发送"
				}
			}

			// 更新数据库中的最后IP（仅保存监控的类型）
			if shouldMonitor("public_ipv4") && len(currentIPs.PublicIPv4) > 0 {
				SaveLastIPs("public_ipv4", currentIPs.PublicIPv4)
			}
			if shouldMonitor("public_ipv6") && len(currentIPs.PublicIPv6) > 0 {
				SaveLastIPs("public_ipv6", currentIPs.PublicIPv6)
			}
			if shouldMonitor("private_ipv4") && len(currentIPs.PrivateIPv4) > 0 {
				SaveLastIPs("private_ipv4", currentIPs.PrivateIPv4)
			}
			if shouldMonitor("private_ipv6") && len(currentIPs.PrivateIPv6) > 0 {
				SaveLastIPs("private_ipv6", currentIPs.PrivateIPv6)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// 获取监控状态
func handleMonitorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	monitorMu.Lock()
	running := monitorTicker != nil
	monitorMu.Unlock()

	monitorCfg, _ := GetMonitorConfig()
	status := struct {
		AutoMode        bool     `json:"auto_mode"`
		Running         bool     `json:"running"`
		IntervalMinutes int      `json:"interval_minutes"`
		MonitorTypes    []string `json:"monitor_types"`
	}{
		AutoMode:        monitorCfg.AutoMode,
		Running:         running,
		IntervalMinutes: monitorCfg.IntervalMinutes,
		MonitorTypes:    monitorCfg.MonitorTypes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// 获取日志内容（应用日志）
func handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	level := r.URL.Query().Get("level")

	logs, err := GetAppLogs(limit, level)
	if err != nil {
		http.Error(w, fmt.Sprintf("获取日志失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// 获取应用日志
func handleAppLogs(w http.ResponseWriter, r *http.Request) {
	handleLogs(w, r)
}

// 日志配置
func handleLogConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取日志配置
		monitorCfg, _ := GetMonitorConfig()
		result := struct {
			RetentionHours int `json:"retention_hours"`
		}{
			RetentionHours: monitorCfg.LogRetentionHours,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)

	case http.MethodPost:
		// 更新日志配置
		var req struct {
			RetentionHours int `json:"retention_hours"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "无效的请求数据", http.StatusBadRequest)
			return
		}

		if req.RetentionHours < 1 {
			req.RetentionHours = 1
		}
		if req.RetentionHours > 8760 { // 最多一年
			req.RetentionHours = 8760
		}

		// 保存到数据库
		monitorCfg, _ := GetMonitorConfig()
		monitorCfg.LogRetentionHours = req.RetentionHours
		SaveMonitorConfig(monitorCfg)

		// 立即执行清理
		CleanOldLogs(req.RetentionHours)

		DBLogInfo("日志保留时间已更新为: %d 小时", req.RetentionHours)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"retention_hours": req.RetentionHours,
		})

	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}

// 手动清理日志
func handleCleanLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RetentionHours int `json:"retention_hours"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		monitorCfg, _ := GetMonitorConfig()
		req.RetentionHours = monitorCfg.LogRetentionHours
	}

	// 允许删除所有日志（retentionHours = 0）
	if req.RetentionHours < 0 {
		req.RetentionHours = 0
	}

	// 记录删除前的操作
	DBLogInfo("用户手动清理日志: 保留%d小时内的日志", req.RetentionHours)

	deleted, err := CleanOldLogsWithCount(req.RetentionHours)
	if err != nil {
		DBLogError("手动清理日志失败: %v", err)
		http.Error(w, fmt.Sprintf("清理日志失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 记录删除结果
	DBLogInfo("手动清理日志成功，删除了 %d 条记录", deleted)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"deleted": deleted,
	})
}

// IP服务列表
func handleIPServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	ipType := r.URL.Query().Get("type")
	services, err := GetIPServices(ipType)
	if err != nil {
		http.Error(w, fmt.Sprintf("获取IP服务列表失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// 获取单个IP服务
func handleGetIPServiceByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "无效的ID", http.StatusBadRequest)
		return
	}

	service, err := GetIPServiceByID(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("获取服务失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}

// 测试单个IP服务
func handleTestIPService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL  string `json:"url"`
		Type string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if req.URL == "" || req.Type == "" {
		http.Error(w, "URL和类型不能为空", http.StatusBadRequest)
		return
	}

	   DBLogInfo("用户测试IP服务: [%s] %s", req.Type, req.URL)

	   // 查找服务ID
	   var serviceID int64 = 0
	   services, _ := GetIPServices("")
	   norm := func(s string) string {
		   return strings.TrimRight(strings.ToLower(s), "/")
	   }
	   for _, svc := range services {
		   if norm(svc.URL) == norm(req.URL) && svc.Type == req.Type {
			   serviceID = svc.ID
			   break
		   }
	   }

	   result := TestIPService(req.URL, req.Type)

	   // 记录测试结果到应用日志
	   if result.Success {
		   DBLogInfo("IP服务测试成功: [%s] %s -> %s (%dms)", req.Type, req.URL, result.IP, result.Duration)
	   } else {
		   DBLogWarn("IP服务测试失败: [%s] %s -> %s", req.Type, req.URL, result.Error)
	   }

	   // 更新服务统计（如果有ID）
	   if serviceID > 0 {
		   UpdateServiceStats(serviceID, result.Success, result.IP, result.Duration)
	   }

	   w.Header().Set("Content-Type", "application/json")
	   json.NewEncoder(w).Encode(result)
}

// 添加IP服务
func handleAddIPService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Type     string `json:"type"`
		Priority int    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.URL == "" || req.Type == "" {
		http.Error(w, "名称、URL和类型不能为空", http.StatusBadRequest)
		return
	}

	if req.Type != "ipv4" && req.Type != "ipv6" {
		http.Error(w, "类型必须是ipv4或ipv6", http.StatusBadRequest)
		return
	}

	DBLogInfo("用户尝试添加IP服务: %s (%s) - %s", req.Name, req.Type, req.URL)

	// 先测试服务是否可用
	result := TestIPService(req.URL, req.Type)
	if !result.Success {
		DBLogWarn("添加IP服务失败 - 服务测试失败: %s (%s) - %s, 错误: %s", req.Name, req.Type, req.URL, result.Error)
		http.Error(w, fmt.Sprintf("服务测试失败: %s", result.Error), http.StatusBadRequest)
		return
	}

	// 添加服务
	service, err := AddIPService(req.Name, req.URL, req.Type, req.Priority)
	if err != nil {
		DBLogWarn("添加IP服务失败: %s (%s) - %s, 错误: %v", req.Name, req.Type, req.URL, err)
		http.Error(w, fmt.Sprintf("添加服务失败: %v", err), http.StatusInternalServerError)
		return
	}

	DBLogInfo("添加IP服务成功: %s (%s) - %s", req.Name, req.Type, req.URL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"service": service,
		"test_ip": result.IP,
	})
}

// 更新IP服务
func handleUpdateIPService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID       int64 `json:"id"`
		Enabled  bool  `json:"enabled"`
		Priority int   `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	// 获取服务名称用于日志
	serviceName := "未知服务"
	if svc, err := GetIPServiceByID(req.ID); err == nil {
		serviceName = svc.Name
	}

	status := "启用"
	if !req.Enabled {
		status = "停用"
	}

	if err := UpdateIPService(req.ID, req.Enabled, req.Priority); err != nil {
		DBLogWarn("更新IP服务失败: %s, 状态=%s, 优先级=%d, 错误: %v", serviceName, status, req.Priority, err)
		http.Error(w, fmt.Sprintf("更新服务失败: %v", err), http.StatusInternalServerError)
		return
	}

	DBLogInfo("更新IP服务成功: %s, 状态=%s, 优先级=%d", serviceName, status, req.Priority)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// 删除IP服务
func handleDeleteIPService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	// 先获取服务名称用于日志
	serviceName := "未知服务"
	serviceURL := ""
	if svc, err := GetIPServiceByID(req.ID); err == nil {
		serviceName = svc.Name
		serviceURL = svc.URL
	}

	if err := DeleteIPService(req.ID); err != nil {
		DBLogWarn("删除IP服务失败: %s (%s), 错误: %v", serviceName, serviceURL, err)
		http.Error(w, fmt.Sprintf("删除服务失败: %v", err), http.StatusInternalServerError)
		return
	}

	DBLogInfo("删除IP服务成功: %s (%s)", serviceName, serviceURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ==================== 加密解密函数 ====================

// deriveKey 从密码派生AES密钥（32字节，用于AES-256）
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// encrypt 使用AES-GCM加密字符串
func encrypt(plaintext, password string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt 使用AES-GCM解密字符串
func decrypt(ciphertext, password string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	key := deriveKey(password)
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64解码失败: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("密文太短")
	}

	nonce, ciphertextBytes := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("解密失败，密钥可能不正确")
	}

	return string(plaintext), nil
}

// ==================== 导出导入数据结构 ====================

// ExportData 导出数据结构
type ExportData struct {
	Version       string         `json:"version"`
	ExportTime    string         `json:"export_time"`
	EmailConfig   EmailExport    `json:"email_config"`
	MonitorConfig MonitorExport  `json:"monitor_config"`
	IPServices    []IPServiceExport `json:"ip_services"`
}

// EmailExport 邮件配置导出
type EmailExport struct {
	SenderEmail       string   `json:"sender_email"`
	SenderPassword    string   `json:"sender_password"` // 加密后的密码
	SMTPServer        string   `json:"smtp_server"`
	SMTPPort          int      `json:"smtp_port"`
	Recipients        []string `json:"recipients"`
	PasswordEncrypted bool     `json:"password_encrypted"` // 标记密码是否已加密
}

// MonitorExport 监控配置导出
type MonitorExport struct {
	AutoMode          bool     `json:"auto_mode"`
	IntervalMinutes   int      `json:"interval_minutes"`
	MonitorTypes      []string `json:"monitor_types"`
	LogRetentionHours int      `json:"log_retention_hours"`
}

// IPServiceExport IP服务导出
type IPServiceExport struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
}

// ==================== 导出处理 ====================

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EncryptKey string `json:"encrypt_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if req.EncryptKey == "" {
		http.Error(w, "加密密钥不能为空", http.StatusBadRequest)
		return
	}

	DBLogInfo("用户开始导出配置")

	// 从数据库读取配置
	emailCfg, _ := GetEmailConfig()
	monitorCfg, _ := GetMonitorConfig()

	// 构建导出数据
	exportData := ExportData{
		Version:    "2.0",
		ExportTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// 邮件配置
	encryptedPassword := ""
	passwordEncrypted := false
	if emailCfg.SenderPassword != "" {
		var err error
		encryptedPassword, err = encrypt(emailCfg.SenderPassword, req.EncryptKey)
		if err != nil {
			DBLogError("导出配置失败 - 加密密码失败: %v", err)
			http.Error(w, fmt.Sprintf("加密密码失败: %v", err), http.StatusInternalServerError)
			return
		}
		passwordEncrypted = true
	}

	exportData.EmailConfig = EmailExport{
		SenderEmail:       emailCfg.SenderEmail,
		SenderPassword:    encryptedPassword,
		SMTPServer:        emailCfg.SMTPServer,
		SMTPPort:          emailCfg.SMTPPort,
		Recipients:        emailCfg.Recipients,
		PasswordEncrypted: passwordEncrypted,
	}

	// 监控配置
	exportData.MonitorConfig = MonitorExport{
		AutoMode:          monitorCfg.AutoMode,
		IntervalMinutes:   monitorCfg.IntervalMinutes,
		MonitorTypes:      monitorCfg.MonitorTypes,
		LogRetentionHours: monitorCfg.LogRetentionHours,
	}

	// IP服务列表
	services, err := GetIPServices("")
	if err != nil {
		DBLogError("导出配置失败 - 获取IP服务失败: %v", err)
		http.Error(w, fmt.Sprintf("获取IP服务失败: %v", err), http.StatusInternalServerError)
		return
	}

	for _, svc := range services {
		exportData.IPServices = append(exportData.IPServices, IPServiceExport{
			Name:     svc.Name,
			URL:      svc.URL,
			Type:     svc.Type,
			Enabled:  svc.Enabled,
			Priority: svc.Priority,
		})
	}

	DBLogInfo("导出配置成功: 邮件配置1份, 监控配置1份, IP服务%d个", len(exportData.IPServices))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=ip-monitor-config.json")
	json.NewEncoder(w).Encode(exportData)
}

// ==================== 导入处理 ====================

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DecryptKey string     `json:"decrypt_key"`
		ImportMode string     `json:"import_mode"` // "smart" 或 "overwrite"
		Data       ExportData `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if req.DecryptKey == "" {
		http.Error(w, "解密密钥不能为空", http.StatusBadRequest)
		return
	}

	// 默认智能导入
	if req.ImportMode == "" {
		req.ImportMode = "smart"
	}

	modeText := "智能导入"
	if req.ImportMode == "overwrite" {
		modeText = "覆盖导入"
	}
	DBLogInfo("用户开始%s配置", modeText)

	// 解密密码
	decryptedPassword := ""
	if req.Data.EmailConfig.PasswordEncrypted && req.Data.EmailConfig.SenderPassword != "" {
		var err error
		decryptedPassword, err = decrypt(req.Data.EmailConfig.SenderPassword, req.DecryptKey)
		if err != nil {
			DBLogError("导入配置失败 - 解密密码失败: %v", err)
			http.Error(w, fmt.Sprintf("解密密码失败: %v（密钥可能不正确）", err), http.StatusBadRequest)
			return
		}
	} else if !req.Data.EmailConfig.PasswordEncrypted {
		decryptedPassword = req.Data.EmailConfig.SenderPassword
	}

	if req.ImportMode == "overwrite" {
		// 覆盖导入：整体替换配置
		emailCfg := &EmailConfig{
			SenderEmail:    req.Data.EmailConfig.SenderEmail,
			SenderPassword: decryptedPassword,
			SMTPServer:     req.Data.EmailConfig.SMTPServer,
			SMTPPort:       req.Data.EmailConfig.SMTPPort,
			Recipients:     req.Data.EmailConfig.Recipients,
		}
		monitorCfg := &MonitorConfig{
			AutoMode:          req.Data.MonitorConfig.AutoMode,
			IntervalMinutes:   req.Data.MonitorConfig.IntervalMinutes,
			MonitorTypes:      req.Data.MonitorConfig.MonitorTypes,
			LogRetentionHours: req.Data.MonitorConfig.LogRetentionHours,
		}

		// 保存到数据库
		if err := SaveEmailConfig(emailCfg); err != nil {
			DBLogError("导入配置失败 - 保存邮件配置失败: %v", err)
			http.Error(w, fmt.Sprintf("保存邮件配置失败: %v", err), http.StatusInternalServerError)
			return
		}
		if err := SaveMonitorConfig(monitorCfg); err != nil {
			DBLogError("导入配置失败 - 保存监控配置失败: %v", err)
			http.Error(w, fmt.Sprintf("保存监控配置失败: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// 智能导入：只更新非空字段
		emailCfg, _ := GetEmailConfig()
		monitorCfg, _ := GetMonitorConfig()

		if req.Data.EmailConfig.SenderEmail != "" {
			emailCfg.SenderEmail = req.Data.EmailConfig.SenderEmail
		}
		if decryptedPassword != "" {
			emailCfg.SenderPassword = decryptedPassword
		}
		if req.Data.EmailConfig.SMTPServer != "" {
			emailCfg.SMTPServer = req.Data.EmailConfig.SMTPServer
		}
		if req.Data.EmailConfig.SMTPPort > 0 {
			emailCfg.SMTPPort = req.Data.EmailConfig.SMTPPort
		}
		if req.Data.EmailConfig.Recipients != nil {
			emailCfg.Recipients = req.Data.EmailConfig.Recipients
		}

		// 更新监控配置
		monitorCfg.AutoMode = req.Data.MonitorConfig.AutoMode
		if req.Data.MonitorConfig.IntervalMinutes > 0 {
			monitorCfg.IntervalMinutes = req.Data.MonitorConfig.IntervalMinutes
		}
		if req.Data.MonitorConfig.MonitorTypes != nil {
			monitorCfg.MonitorTypes = req.Data.MonitorConfig.MonitorTypes
		}
		if req.Data.MonitorConfig.LogRetentionHours > 0 {
			monitorCfg.LogRetentionHours = req.Data.MonitorConfig.LogRetentionHours
		}

		// 保存到数据库
		if err := SaveEmailConfig(emailCfg); err != nil {
			DBLogError("导入配置失败 - 保存邮件配置失败: %v", err)
			http.Error(w, fmt.Sprintf("保存邮件配置失败: %v", err), http.StatusInternalServerError)
			return
		}
		if err := SaveMonitorConfig(monitorCfg); err != nil {
			DBLogError("导入配置失败 - 保存监控配置失败: %v", err)
			http.Error(w, fmt.Sprintf("保存监控配置失败: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// 导入IP服务
	importedServices := 0
	skippedServices := 0
	deletedServices := int64(0)

	// 覆盖模式：先删除所有现有IP服务
	if req.ImportMode == "overwrite" {
		var err error
		deletedServices, err = DeleteAllIPServices()
		if err != nil {
			DBLogError("导入配置失败 - 删除现有服务失败: %v", err)
			http.Error(w, fmt.Sprintf("删除现有服务失败: %v", err), http.StatusInternalServerError)
			return
		}
		DBLogInfo("覆盖导入: 已删除现有IP服务%d个", deletedServices)
	}

	for _, svc := range req.Data.IPServices {
		// 尝试添加服务（如果URL已存在会失败，忽略错误继续）
		_, err := AddIPService(svc.Name, svc.URL, svc.Type, svc.Priority)
		if err != nil {
			// URL已存在，跳过（仅在智能导入模式下可能发生）
			skippedServices++
			continue
		}
		importedServices++
	}

	// 重启监控（如果需要）
	go restartIPMonitor()

	var message string
	if req.ImportMode == "overwrite" {
		message = fmt.Sprintf("覆盖导入成功！删除原有服务%d个，导入IP服务%d个", deletedServices, importedServices)
		DBLogInfo("覆盖导入配置成功: 邮件配置已更新, 监控配置已更新, 删除原有服务%d个, 新增IP服务%d个", 
			deletedServices, importedServices)
	} else {
		message = fmt.Sprintf("智能导入成功！新增IP服务%d个，跳过%d个（已存在）", importedServices, skippedServices)
		DBLogInfo("智能导入配置成功: 邮件配置已更新, 监控配置已更新, IP服务新增%d个, 跳过%d个(已存在)", 
			importedServices, skippedServices)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":           true,
		"import_mode":       req.ImportMode,
		"imported_services": importedServices,
		"skipped_services":  skippedServices,
		"deleted_services":  deletedServices,
		"message":           message,
	})
}
