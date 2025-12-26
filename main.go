package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

var (
	port       = flag.Int("port", 8543, "服务监听端口（默认8543）")
	configFile = "config.json"
	dbFile     = "data.db"
)

type Config struct {
	SenderEmail       string   `json:"sender_email"`
	SenderPassword    string   `json:"sender_password"`
	SMTPServer        string   `json:"smtp_server"`
	SMTPPort          int      `json:"smtp_port"`
	Recipients        []string `json:"recipients"`
	LastPublicIPv4    string   `json:"last_public_ipv4"`
	LastPublicIPv6    string   `json:"last_public_ipv6"`
	LastAllIPs        *IPInfo  `json:"last_all_ips"`
	AutoMode          bool     `json:"auto_mode"`
	IntervalMinutes   int      `json:"interval_minutes"`
	MonitorTypes      []string `json:"monitor_types"`
	LogRetentionHours int      `json:"log_retention_hours"` // 日志保留小时数
}

var config Config
var (
	monitorTicker *time.Ticker
	monitorStop   chan bool
	monitorMu     sync.Mutex
)

func main() {
	flag.Parse()

	// 加载配置
	loadConfig()

	// 初始化数据库
	if err := InitDatabase(dbFile); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer CloseDatabase()

	DBLogInfo("IP地址监控系统启动")

	// 启动日志清理定时任务（每小时清理一次）
	retentionHours := config.LogRetentionHours
	if retentionHours <= 0 {
		retentionHours = 72 // 默认保留72小时（3天）
	}
	StartLogCleanupScheduler(retentionHours)

	// 根据配置启动IP监控
	if config.AutoMode {
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
	http.HandleFunc("/api/logs/fetch", handleFetchLogs)
	http.HandleFunc("/api/logs/config", handleLogConfig)
	http.HandleFunc("/api/logs/clean", handleCleanLogs)
	// IP服务管理API
	http.HandleFunc("/api/ip-services", handleIPServices)
	http.HandleFunc("/api/ip-services/get", handleGetIPServiceByID)
	http.HandleFunc("/api/ip-services/test", handleTestIPService)
	http.HandleFunc("/api/ip-services/add", handleAddIPService)
	http.HandleFunc("/api/ip-services/update", handleUpdateIPService)
	http.HandleFunc("/api/ip-services/delete", handleDeleteIPService)

	addr := fmt.Sprintf(":%d", *port)
	DBLogInfo("服务器启动在端口 %d", *port)
	log.Printf("服务器启动在端口 %d", *port)
	log.Printf("请访问: http://localhost:%d", *port)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("启动服务器失败:", err)
	}
}

func loadConfig() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Println("未找到配置文件，使用默认配置")
		config = Config{
			SMTPPort:          587,
			Recipients:        []string{},
			AutoMode:          false,
			IntervalMinutes:   30,
			MonitorTypes:      []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"},
			LogRetentionHours: 72, // 默认保留72小时（3天）
		}
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		log.Println("解析配置文件失败:", err)
	}

	// 默认值处理
	if config.IntervalMinutes <= 0 {
		config.IntervalMinutes = 30
	}
	if len(config.MonitorTypes) == 0 {
		config.MonitorTypes = []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"}
	}
	if config.LogRetentionHours <= 0 {
		config.LogRetentionHours = 72
	}
}

func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
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

	interval := time.Duration(config.IntervalMinutes) * time.Minute
	monitorTicker = time.NewTicker(interval)
	monitorStop = make(chan bool)

	DBLogInfo("启动自动监控，间隔: %d 分钟", config.IntervalMinutes)

	go func() {
		// 首次检查
		checkAndNotifyIPChange()

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
}

func stopIPMonitor() {
	monitorMu.Lock()
	defer monitorMu.Unlock()

	if monitorTicker != nil {
		monitorTicker.Stop()
		monitorTicker = nil
	}
	if monitorStop != nil {
		close(monitorStop)
		monitorStop = nil
	}
	DBLogInfo("自动监控已停止")
}

func restartIPMonitor() {
	stopIPMonitor()
	if config.AutoMode {
		startIPMonitor()
	}
}

func checkAndNotifyIPChange() {
	DBLogInfo("开始检查IP地址...")

	// 重新加载配置文件，确保使用最新的配置
	loadConfig()

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

	// 保存IP记录
	if ipv4 != "" {
		SaveIPRecord("public_ipv4", ipv4)
	}
	if ipv6 != "" {
		SaveIPRecord("public_ipv6", ipv6)
	}

	// 第一次运行，LastAllIPs 为空，只记录不通知
	if config.LastAllIPs == nil {
		DBLogInfo("首次运行，记录当前IP地址（不发送通知）")
		config.LastAllIPs = &currentIPs
		config.LastPublicIPv4 = ipv4
		config.LastPublicIPv6 = ipv6
		saveConfig()
		return
	}

	// 检查上次记录是否为空（也是首次有效记录）
	isFirstRecord := len(config.LastAllIPs.PublicIPv4) == 0 &&
		len(config.LastAllIPs.PublicIPv6) == 0 &&
		len(config.LastAllIPs.PrivateIPv4) == 0 &&
		len(config.LastAllIPs.PrivateIPv6) == 0

	if isFirstRecord {
		DBLogInfo("首次记录IP地址（不发送通知）")
		config.LastAllIPs = &currentIPs
		config.LastPublicIPv4 = ipv4
		config.LastPublicIPv6 = ipv6
		saveConfig()
		return
	}

	// 处理断网情况
	if !networkOK {
		DBLogWarn("网络断开，IP地址设为占位符，等待网络恢复")
		// 断网时记录占位符IP，但不发送邮件
		// 这样网络恢复后第一时间能检测到变化并发送通知
		currentIPs.PublicIPv4 = []string{DisconnectedIPv4}
		currentIPs.PublicIPv6 = []string{DisconnectedIPv6}
		config.LastAllIPs = &currentIPs
		config.LastPublicIPv4 = DisconnectedIPv4
		config.LastPublicIPv6 = DisconnectedIPv6
		saveConfig()
		return
	}

	// 处理一个有值一个为空的情况
	oldIPv4 := config.LastPublicIPv4
	oldIPv6 := config.LastPublicIPv6
	
	// 检查是否只有一个IP获取失败
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
			if config.SenderEmail != "" && len(config.Recipients) > 0 {
				sendIPFetchWarningEmail(warningType, oldIPv4, oldIPv6, ipv4, ipv6)
			}
		}
	}

	// 检查是否有变化
	changed, issues := ValidateAndCompareIPs(oldIPv4, oldIPv6, ipv4, ipv6)
	
	// 同时检查私网IP变化
	changes := compareAllIPs(config.LastAllIPs, &currentIPs)
	
	if changed || len(changes) > 0 {
		// 记录详细的IP变化
		for _, issue := range issues {
			DBLogInfo("IP变化: %s", issue)
		}
		for _, change := range changes {
			if len(change.Added) > 0 {
				DBLogInfo("IP变化 [%s] 新增: %v", change.Type, change.Added)
			}
			if len(change.Removed) > 0 {
				DBLogInfo("IP变化 [%s] 移除: %v", change.Type, change.Removed)
			}
		}

		// 发送通知邮件
		if config.SenderEmail != "" && len(config.Recipients) > 0 {
			err := sendAllIPChangeNotification(config.LastAllIPs, &currentIPs, changes)
			if err != nil {
				DBLogError("发送邮件失败: %v", err)
			} else {
				DBLogInfo("邮件通知发送成功，收件人: %v", config.Recipients)
			}
		}

		// 更新保存的IP
		config.LastAllIPs = &currentIPs
		config.LastPublicIPv4 = ipv4
		config.LastPublicIPv6 = ipv6
		saveConfig()
	} else {
		DBLogInfo("所有IP地址无变化")
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
	for _, t := range config.MonitorTypes {
		if t == ipType {
			return true
		}
	}
	return false
}

// 比较所有IP，返回变化列表（根据监控类型过滤）
func compareAllIPs(oldIPs, newIPs *IPInfo) []IPChange {
	var changes []IPChange
	
	// 比较公网IPv4
	if shouldMonitor("public_ipv4") {
		if added, removed := compareIPList(oldIPs.PublicIPv4, newIPs.PublicIPv4); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "公网IPv4", Added: added, Removed: removed})
		}
	}
	
	// 比较公网IPv6
	if shouldMonitor("public_ipv6") {
		if added, removed := compareIPList(oldIPs.PublicIPv6, newIPs.PublicIPv6); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "公网IPv6", Added: added, Removed: removed})
		}
	}
	
	// 比较私网IPv4
	if shouldMonitor("private_ipv4") {
		if added, removed := compareIPList(oldIPs.PrivateIPv4, newIPs.PrivateIPv4); len(added) > 0 || len(removed) > 0 {
			changes = append(changes, IPChange{Type: "私网IPv4", Added: added, Removed: removed})
		}
	}
	
	// 比较私网IPv6
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

	// 不返回密码
	safeConfig := struct {
		SenderEmail     string   `json:"sender_email"`
		SMTPServer      string   `json:"smtp_server"`
		SMTPPort        int      `json:"smtp_port"`
		Recipients      []string `json:"recipients"`
		AutoMode        bool     `json:"auto_mode"`
		IntervalMinutes int      `json:"interval_minutes"`
	}{
		SenderEmail:     config.SenderEmail,
		SMTPServer:      config.SMTPServer,
		SMTPPort:        config.SMTPPort,
		Recipients:      config.Recipients,
		AutoMode:        config.AutoMode,
		IntervalMinutes: config.IntervalMinutes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(safeConfig)
}

// 保存邮件配置（独立模块）
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

	// 只更新邮件相关配置
	if emailConfig.SenderEmail != "" {
		config.SenderEmail = emailConfig.SenderEmail
	}
	if emailConfig.SenderPassword != "" {
		config.SenderPassword = emailConfig.SenderPassword
	}
	if emailConfig.SMTPServer != "" {
		config.SMTPServer = emailConfig.SMTPServer
	}
	if emailConfig.SMTPPort > 0 {
		config.SMTPPort = emailConfig.SMTPPort
	}
	if emailConfig.Recipients != nil {
		config.Recipients = emailConfig.Recipients
	}

	if err := saveConfig(); err != nil {
		DBLogError("保存邮件配置失败: %v", err)
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	DBLogInfo("用户保存邮件配置成功: 发件人=%s, SMTP=%s:%d, 收件人=%v", 
		config.SenderEmail, config.SMTPServer, config.SMTPPort, config.Recipients)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// 保存监控配置（独立模块）
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

	// 检查是否需要重启监控
	needRestart := config.AutoMode != monitorConfig.AutoMode || 
		config.IntervalMinutes != monitorConfig.IntervalMinutes

	// 只更新监控相关配置
	config.AutoMode = monitorConfig.AutoMode
	if monitorConfig.IntervalMinutes > 0 {
		config.IntervalMinutes = monitorConfig.IntervalMinutes
	}
	if monitorConfig.MonitorTypes != nil {
		config.MonitorTypes = monitorConfig.MonitorTypes
	}

	if err := saveConfig(); err != nil {
		DBLogError("保存监控配置失败: %v", err)
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	modeStr := "手动"
	if config.AutoMode {
		modeStr = fmt.Sprintf("自动(每%d分钟)", config.IntervalMinutes)
	}
	DBLogInfo("用户保存监控配置成功: 模式=%s, 监控类型=%v", modeStr, config.MonitorTypes)

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

	if config.SenderEmail == "" || len(config.Recipients) == 0 {
		http.Error(w, "请先配置发件人和收件人", http.StatusBadRequest)
		return
	}

	DBLogInfo("用户发送测试邮件到: %v", config.Recipients)

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
	log.Println("手动触发IP检查...")

	// 重新加载配置文件，确保使用最新的配置
	loadConfig()

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

	// 检查是否是首次记录
	isFirstRecord := config.LastAllIPs == nil ||
		(len(config.LastAllIPs.PublicIPv4) == 0 &&
			len(config.LastAllIPs.PublicIPv6) == 0 &&
			len(config.LastAllIPs.PrivateIPv4) == 0 &&
			len(config.LastAllIPs.PrivateIPv6) == 0)

	if isFirstRecord {
		// 首次记录，保存当前IP，不发送通知
		config.LastAllIPs = &currentIPs
		config.LastPublicIPv4 = ipv4
		config.LastPublicIPv6 = ipv6
		saveConfig()

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
			Message:    "首次记录IP地址完成，后续变化将会通知",
			NetworkOK:  networkOK,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	changes := compareAllIPs(config.LastAllIPs, &currentIPs)
	changed := len(changes) > 0

	result := struct {
		Changed    bool       `json:"changed"`
		Changes    []IPChange `json:"changes"`
		CurrentIPs *IPInfo    `json:"current_ips"`
		EmailSent  bool       `json:"email_sent"`
		Message    string     `json:"message"`
		NetworkOK  bool       `json:"network_ok"`
	}{
		Changed:    changed,
		Changes:    changes,
		CurrentIPs: &currentIPs,
		EmailSent:  false,
		Message:    "所有IP地址无变化",
		NetworkOK:  networkOK,
	}

	if !networkOK {
		result.Message = "网络断开，无法获取公网IP"
	} else if changed {
		result.Message = "检测到IP地址变化"

		// 发送通知邮件
		if config.SenderEmail != "" && len(config.Recipients) > 0 {
			err := sendAllIPChangeNotification(config.LastAllIPs, &currentIPs, changes)
			if err != nil {
				result.Message = fmt.Sprintf("IP变化已检测，但邮件发送失败: %v", err)
			} else {
				result.EmailSent = true
				result.Message = "IP变化已检测，邮件通知已发送"
			}
		}

		// 更新保存的IP
		config.LastAllIPs = &currentIPs
		config.LastPublicIPv4 = ipv4
		config.LastPublicIPv6 = ipv6
		saveConfig()
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

	status := struct {
		AutoMode        bool     `json:"auto_mode"`
		Running         bool     `json:"running"`
		IntervalMinutes int      `json:"interval_minutes"`
		MonitorTypes    []string `json:"monitor_types"`
	}{
		AutoMode:        config.AutoMode,
		Running:         running,
		IntervalMinutes: config.IntervalMinutes,
		MonitorTypes:    config.MonitorTypes,
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

// 获取IP获取日志
func handleFetchLogs(w http.ResponseWriter, r *http.Request) {
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

	logs, err := GetIPFetchLogs(limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("获取日志失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// 日志配置
func handleLogConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取日志配置
		result := struct {
			RetentionHours int `json:"retention_hours"`
		}{
			RetentionHours: config.LogRetentionHours,
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

		config.LogRetentionHours = req.RetentionHours
		saveConfig()

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
		req.RetentionHours = config.LogRetentionHours
	}

	if req.RetentionHours < 1 {
		req.RetentionHours = 1
	}

	DBLogInfo("用户手动清理日志: 保留%d小时内的日志", req.RetentionHours)

	deleted, err := CleanOldLogsWithCount(req.RetentionHours)
	if err != nil {
		DBLogError("手动清理日志失败: %v", err)
		http.Error(w, fmt.Sprintf("清理日志失败: %v", err), http.StatusInternalServerError)
		return
	}

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

	   // 记录测试日志
	   fetchLog := &IPFetchLog{
		   ServiceID:  serviceID,
		   ServiceURL: req.URL,
		   IPType:     req.Type,
		   Success:    result.Success,
		   IP:         result.IP,
		   StatusCode: result.StatusCode,
		   Error:      result.Error,
		   Duration:   result.Duration,
	   }
	   SaveIPFetchLog(fetchLog)

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
