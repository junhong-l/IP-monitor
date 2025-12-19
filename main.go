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
	SenderEmail    string   `json:"sender_email"`
	SenderPassword string   `json:"sender_password"`
	SMTPServer     string   `json:"smtp_server"`
	SMTPPort       int      `json:"smtp_port"`
	Recipients     []string `json:"recipients"`
	LastPublicIPs  []string `json:"last_public_ips"`
	AutoMode       bool     `json:"auto_mode"`
	IntervalMinutes int     `json:"interval_minutes"`
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
	http.HandleFunc("/api/config/save", handleSaveConfig)
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
			LastPublicIPs:   []string{},
			AutoMode:        false,
			IntervalMinutes: 30,
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
	
	currentIPs := getCurrentPublicIPs()
	
	// 检查是否有变化
	if hasIPChanged(config.LastPublicIPs, currentIPs) {
		log.Println("检测到公网IP变化")
		
		// 发送通知邮件
		if config.SenderEmail != "" && len(config.Recipients) > 0 {
			err := sendIPChangeNotification(config.LastPublicIPs, currentIPs)
			if err != nil {
				log.Printf("发送邮件失败: %v", err)
			} else {
				log.Println("邮件通知发送成功")
			}
		}
		
		// 更新保存的IP
		config.LastPublicIPs = currentIPs
		saveConfig()
	} else {
		log.Println("公网IP无变化")
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

func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var newConfig struct {
		SenderEmail     string   `json:"sender_email"`
		SenderPassword  string   `json:"sender_password"`
		SMTPServer      string   `json:"smtp_server"`
		SMTPPort        int      `json:"smtp_port"`
		Recipients      []string `json:"recipients"`
		AutoMode        bool     `json:"auto_mode"`
		IntervalMinutes int      `json:"interval_minutes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	// 检查是否需要重启监控
	needRestart := config.AutoMode != newConfig.AutoMode || 
		config.IntervalMinutes != newConfig.IntervalMinutes

	// 更新配置
	if newConfig.SenderEmail != "" {
		config.SenderEmail = newConfig.SenderEmail
	}
	if newConfig.SenderPassword != "" {
		config.SenderPassword = newConfig.SenderPassword
	}
	if newConfig.SMTPServer != "" {
		config.SMTPServer = newConfig.SMTPServer
	}
	if newConfig.SMTPPort > 0 {
		config.SMTPPort = newConfig.SMTPPort
	}
	config.Recipients = newConfig.Recipients
	config.AutoMode = newConfig.AutoMode
	if newConfig.IntervalMinutes > 0 {
		config.IntervalMinutes = newConfig.IntervalMinutes
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
	
	currentIPs := getCurrentPublicIPs()
	changed := hasIPChanged(config.LastPublicIPs, currentIPs)
	
	result := struct {
		Changed   bool     `json:"changed"`
		OldIPs    []string `json:"old_ips"`
		CurrentIPs []string `json:"current_ips"`
		EmailSent bool     `json:"email_sent"`
		Message   string   `json:"message"`
	}{
		Changed:    changed,
		OldIPs:     config.LastPublicIPs,
		CurrentIPs: currentIPs,
		EmailSent:  false,
		Message:    "IP地址无变化",
	}
	
	if changed {
		result.Message = "检测到IP地址变化"
		
		// 发送通知邮件
		if config.SenderEmail != "" && len(config.Recipients) > 0 {
			err := sendIPChangeNotification(config.LastPublicIPs, currentIPs)
			if err != nil {
				result.Message = fmt.Sprintf("IP变化已检测，但邮件发送失败: %v", err)
			} else {
				result.EmailSent = true
				result.Message = "IP变化已检测，邮件通知已发送"
			}
		}
		
		// 更新保存的IP
		config.LastPublicIPs = currentIPs
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
		AutoMode        bool `json:"auto_mode"`
		Running         bool `json:"running"`
		IntervalMinutes int  `json:"interval_minutes"`
	}{
		AutoMode:        config.AutoMode,
		Running:         running,
		IntervalMinutes: config.IntervalMinutes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
