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
	"sync"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

var (
	port       = flag.Int("port", 8543, "服务监听端口（默认8543）")
	configFile = "config.json"
)

type Config struct {
	SenderEmail     string   `json:"sender_email"`
	SenderPassword  string   `json:"sender_password"`
	SMTPServer      string   `json:"smtp_server"`
	SMTPPort        int      `json:"smtp_port"`
	Recipients      []string `json:"recipients"`
	LastAllIPs      *IPInfo  `json:"last_all_ips"`      // 记录上次的所有IP，用于对比变化
	AutoMode        bool     `json:"auto_mode"`
	IntervalMinutes int      `json:"interval_minutes"`
	MonitorTypes    []string `json:"monitor_types"`     // 监控类型: public_ipv4, public_ipv6, private_ipv4, private_ipv6
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

	addr := fmt.Sprintf(":%d", *port)
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
			SMTPPort:        587,
			Recipients:      []string{},
			AutoMode:        false,
			IntervalMinutes: 30,
			MonitorTypes:    []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"}, // 默认监控所有
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
	// 如果没有设置监控类型，默认监控所有
	if len(config.MonitorTypes) == 0 {
		config.MonitorTypes = []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"}
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
	
	log.Printf("启动自动监控，间隔: %d 分钟", config.IntervalMinutes)
	
	go func() {
		// 首次检查
		checkAndNotifyIPChange()
		
		for {
			select {
			case <-monitorTicker.C:
				checkAndNotifyIPChange()
			case <-monitorStop:
				log.Println("停止自动监控")
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
	log.Println("自动监控已停止")
}

func restartIPMonitor() {
	stopIPMonitor()
	if config.AutoMode {
		startIPMonitor()
	}
}

func checkAndNotifyIPChange() {
	log.Println("开始检查IP地址...")
	
	// 重新加载配置文件，确保使用最新的配置
	loadConfig()
	
	currentIPs := getAllIPs()
	
	// 第一次运行，LastAllIPs 为空，只记录不通知
	if config.LastAllIPs == nil {
		log.Println("首次运行，记录当前IP地址（不发送通知）")
		config.LastAllIPs = &currentIPs
		saveConfig()
		return
	}
	
	// 检查上次记录是否为空（也是首次有效记录）
	isFirstRecord := len(config.LastAllIPs.PublicIPv4) == 0 && 
		len(config.LastAllIPs.PublicIPv6) == 0 && 
		len(config.LastAllIPs.PrivateIPv4) == 0 && 
		len(config.LastAllIPs.PrivateIPv6) == 0
	
	if isFirstRecord {
		log.Println("首次记录IP地址（不发送通知）")
		config.LastAllIPs = &currentIPs
		saveConfig()
		return
	}
	
	// 检查是否有变化
	changes := compareAllIPs(config.LastAllIPs, &currentIPs)
	if len(changes) > 0 {
		log.Printf("检测到IP变化: %v", changes)
		
		// 发送通知邮件
		if config.SenderEmail != "" && len(config.Recipients) > 0 {
			err := sendAllIPChangeNotification(config.LastAllIPs, &currentIPs, changes)
			if err != nil {
				log.Printf("发送邮件失败: %v", err)
			} else {
				log.Println("邮件通知发送成功")
			}
		}
		
		// 更新保存的IP
		config.LastAllIPs = &currentIPs
		saveConfig()
	} else {
		log.Println("所有IP地址无变化")
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
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

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
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

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

	err := sendTestEmail()
	if err != nil {
		http.Error(w, fmt.Sprintf("发送测试邮件失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "测试邮件发送成功"})
}

// 手动检查IP变化
func handleCheckIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	log.Println("手动触发IP检查...")
	
	// 重新加载配置文件，确保使用最新的配置
	loadConfig()
	
	currentIPs := getAllIPs()
	
	// 检查是否是首次记录
	isFirstRecord := config.LastAllIPs == nil || 
		(len(config.LastAllIPs.PublicIPv4) == 0 && 
		len(config.LastAllIPs.PublicIPv6) == 0 && 
		len(config.LastAllIPs.PrivateIPv4) == 0 && 
		len(config.LastAllIPs.PrivateIPv6) == 0)
	
	if isFirstRecord {
		// 首次记录，保存当前IP，不发送通知
		config.LastAllIPs = &currentIPs
		saveConfig()
		
		result := struct {
			Changed    bool       `json:"changed"`
			Changes    []IPChange `json:"changes"`
			CurrentIPs *IPInfo    `json:"current_ips"`
			EmailSent  bool       `json:"email_sent"`
			Message    string     `json:"message"`
		}{
			Changed:    false,
			Changes:    []IPChange{},
			CurrentIPs: &currentIPs,
			EmailSent:  false,
			Message:    "首次记录IP地址完成，后续变化将会通知",
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
	}{
		Changed:    changed,
		Changes:    changes,
		CurrentIPs: &currentIPs,
		EmailSent:  false,
		Message:    "所有IP地址无变化",
	}
	
	if changed {
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
