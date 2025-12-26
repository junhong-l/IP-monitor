package main

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	dbMu sync.Mutex
)

// IPService IP获取服务配置
type IPService struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Type          string `json:"type"` // ipv4 或 ipv6
	Enabled       bool   `json:"enabled"`
	Priority      int    `json:"priority"` // 优先级，数字越小越优先
	SuccessCount  int64  `json:"success_count"`
	FailCount     int64  `json:"fail_count"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastFailAt    string `json:"last_fail_at,omitempty"`
	LastIP        string `json:"last_ip,omitempty"`
	AvgDurationMs int64  `json:"avg_duration_ms"`
	CreatedAt     string `json:"created_at"`
}

// IPFetchLog IP获取日志
type IPFetchLog struct {
	ID         int64  `json:"id"`
	ServiceID  int64  `json:"service_id"`
	ServiceURL string `json:"service_url"`
	IPType     string `json:"ip_type"`
	Success    bool   `json:"success"`
	IP         string `json:"ip"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
	Duration   int64  `json:"duration_ms"`
	CreatedAt  string `json:"created_at"`
}

// AppLog 应用日志
type AppLog struct {
	ID        int64  `json:"id"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

// IPRecord IP记录
type IPRecord struct {
	ID         int64  `json:"id"`
	Type       string `json:"type"` // public_ipv4, public_ipv6, private_ipv4, private_ipv6
	IP         string `json:"ip"`
	RecordedAt string `json:"recorded_at"`
}

// InitDatabase 初始化数据库
func InitDatabase(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %v", err)
	}

	// 创建表
	if err := createTables(); err != nil {
		return fmt.Errorf("创建表失败: %v", err)
	}

	// 初始化默认IP服务
	if err := initDefaultIPServices(); err != nil {
		return fmt.Errorf("初始化默认IP服务失败: %v", err)
	}

	return nil
}

// createTables 创建数据库表
func createTables() error {
	tables := []string{
		// IP获取服务表
		`CREATE TABLE IF NOT EXISTS ip_services (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			url TEXT NOT NULL UNIQUE,
			type TEXT NOT NULL CHECK(type IN ('ipv4', 'ipv6')),
			enabled INTEGER DEFAULT 1,
			priority INTEGER DEFAULT 100,
			success_count INTEGER DEFAULT 0,
			fail_count INTEGER DEFAULT 0,
			last_success_at DATETIME,
			last_fail_at DATETIME,
			last_ip TEXT,
			avg_duration_ms INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// IP获取日志表
		`CREATE TABLE IF NOT EXISTS ip_fetch_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id INTEGER,
			service_url TEXT NOT NULL,
			ip_type TEXT NOT NULL,
			success INTEGER NOT NULL,
			ip TEXT,
			status_code INTEGER,
			error TEXT,
			duration_ms INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 应用日志表
		`CREATE TABLE IF NOT EXISTS app_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			level TEXT NOT NULL,
			message TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// IP记录表（记录历史IP）
		`CREATE TABLE IF NOT EXISTS ip_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			ip TEXT NOT NULL,
			recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 配置表
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,

		// 创建索引
		`CREATE INDEX IF NOT EXISTS idx_ip_fetch_logs_created_at ON ip_fetch_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_app_logs_created_at ON app_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_records_type ON ip_records(type)`,
	}

	for _, table := range tables {
		if _, err := db.Exec(table); err != nil {
			return fmt.Errorf("执行SQL失败: %s, 错误: %v", table, err)
		}
	}

	// 迁移：给已存在的ip_services表添加新列
	migrations := []string{
		"ALTER TABLE ip_services ADD COLUMN success_count INTEGER DEFAULT 0",
		"ALTER TABLE ip_services ADD COLUMN fail_count INTEGER DEFAULT 0",
		"ALTER TABLE ip_services ADD COLUMN last_success_at DATETIME",
		"ALTER TABLE ip_services ADD COLUMN last_fail_at DATETIME",
		"ALTER TABLE ip_services ADD COLUMN last_ip TEXT",
		"ALTER TABLE ip_services ADD COLUMN avg_duration_ms INTEGER DEFAULT 0",
	}

	for _, migration := range migrations {
		// 忽略"duplicate column"错误
		db.Exec(migration)
	}

	return nil
}

// initDefaultIPServices 初始化默认IP获取服务
func initDefaultIPServices() error {
	// 检查是否已有数据
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM ip_services").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil // 已有数据，不需要初始化
	}

	// 默认IPv4服务
	ipv4Services := []struct {
		name     string
		url      string
		priority int
	}{
		{"ipify", "https://api.ipify.org", 1},
		{"ipify (api4)", "https://api4.ipify.org", 2},
		{"icanhazip", "https://ipv4.icanhazip.com", 3},
		{"AWS checkip", "https://checkip.amazonaws.com", 4},
		{"ifconfig.me", "https://ifconfig.me/ip", 5},
		{"ip.sb", "https://api-ipv4.ip.sb/ip", 6},
		{"ipecho", "https://ipecho.net/plain", 7},
		{"myexternalip", "https://myexternalip.com/raw", 8},
		{"3322.net", "https://ip.3322.net", 9},
	}

	// 默认IPv6服务
	ipv6Services := []struct {
		name     string
		url      string
		priority int
	}{
		{"ipify (api6)", "https://api6.ipify.org", 1},
		{"icanhazip (v6)", "https://ipv6.icanhazip.com", 2},
		{"ident.me (v6)", "https://v6.ident.me", 3},
		{"ip.sb (v6)", "https://api-ipv6.ip.sb/ip", 4},
	}

	// 插入IPv4服务
	for _, svc := range ipv4Services {
		_, err := db.Exec(
			"INSERT INTO ip_services (name, url, type, enabled, priority) VALUES (?, ?, 'ipv4', 1, ?)",
			svc.name, svc.url, svc.priority,
		)
		if err != nil {
			return err
		}
	}

	// 插入IPv6服务
	for _, svc := range ipv6Services {
		_, err := db.Exec(
			"INSERT INTO ip_services (name, url, type, enabled, priority) VALUES (?, ?, 'ipv6', 1, ?)",
			svc.name, svc.url, svc.priority,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetIPServices 获取IP服务列表
func GetIPServices(ipType string) ([]IPService, error) {
	query := `SELECT id, name, url, type, enabled, priority, 
		COALESCE(success_count, 0), COALESCE(fail_count, 0), 
		COALESCE(last_success_at, ''), COALESCE(last_fail_at, ''), 
		COALESCE(last_ip, ''), COALESCE(avg_duration_ms, 0), created_at 
		FROM ip_services`
	args := []interface{}{}

	if ipType != "" {
		query += " WHERE type = ?"
		args = append(args, ipType)
	}
	query += " ORDER BY priority ASC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []IPService
	for rows.Next() {
		var svc IPService
		var enabled int
		if err := rows.Scan(&svc.ID, &svc.Name, &svc.URL, &svc.Type, &enabled, &svc.Priority,
			&svc.SuccessCount, &svc.FailCount, &svc.LastSuccessAt, &svc.LastFailAt,
			&svc.LastIP, &svc.AvgDurationMs, &svc.CreatedAt); err != nil {
			return nil, err
		}
		svc.Enabled = enabled == 1
		services = append(services, svc)
	}

	return services, nil
}

// GetIPServiceByID 通过ID获取单个IP服务
func GetIPServiceByID(id int64) (*IPService, error) {
	query := `SELECT id, name, url, type, enabled, priority, 
		COALESCE(success_count, 0), COALESCE(fail_count, 0), 
		COALESCE(last_success_at, ''), COALESCE(last_fail_at, ''), 
		COALESCE(last_ip, ''), COALESCE(avg_duration_ms, 0), created_at 
		FROM ip_services WHERE id = ?`
	row := db.QueryRow(query, id)

	var svc IPService
	var enabled int
	if err := row.Scan(&svc.ID, &svc.Name, &svc.URL, &svc.Type, &enabled, &svc.Priority,
		&svc.SuccessCount, &svc.FailCount, &svc.LastSuccessAt, &svc.LastFailAt,
		&svc.LastIP, &svc.AvgDurationMs, &svc.CreatedAt); err != nil {
		return nil, err
	}
	svc.Enabled = enabled == 1
	return &svc, nil
}

// UpdateServiceStats 更新服务统计信息
func UpdateServiceStats(serviceID int64, success bool, ip string, durationMs int64) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	
	if success {
		// 成功：更新成功次数、最后成功时间、最后IP、平均耗时
		_, err := db.Exec(`
			UPDATE ip_services SET 
				success_count = COALESCE(success_count, 0) + 1,
				last_success_at = ?,
				last_ip = ?,
				avg_duration_ms = CASE 
					WHEN COALESCE(success_count, 0) = 0 THEN ?
					ELSE (COALESCE(avg_duration_ms, 0) * COALESCE(success_count, 0) + ?) / (COALESCE(success_count, 0) + 1)
				END
			WHERE id = ?`,
			now, ip, durationMs, durationMs, serviceID)
		return err
	} else {
		// 失败：更新失败次数、最后失败时间
		_, err := db.Exec(`
			UPDATE ip_services SET 
				fail_count = COALESCE(fail_count, 0) + 1,
				last_fail_at = ?
			WHERE id = ?`,
			now, serviceID)
		return err
	}
}

// GetEnabledIPServices 获取启用的IP服务列表
func GetEnabledIPServices(ipType string) ([]IPService, error) {
	query := `SELECT id, name, url, type, enabled, priority, 
		COALESCE(success_count, 0), COALESCE(fail_count, 0), 
		COALESCE(last_success_at, ''), COALESCE(last_fail_at, ''), 
		COALESCE(last_ip, ''), COALESCE(avg_duration_ms, 0), created_at 
		FROM ip_services WHERE enabled = 1`
	args := []interface{}{}

	if ipType != "" {
		query += " AND type = ?"
		args = append(args, ipType)
	}
	query += " ORDER BY priority ASC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []IPService
	for rows.Next() {
		var svc IPService
		var enabled int
		if err := rows.Scan(&svc.ID, &svc.Name, &svc.URL, &svc.Type, &enabled, &svc.Priority,
			&svc.SuccessCount, &svc.FailCount, &svc.LastSuccessAt, &svc.LastFailAt,
			&svc.LastIP, &svc.AvgDurationMs, &svc.CreatedAt); err != nil {
			return nil, err
		}
		svc.Enabled = enabled == 1
		services = append(services, svc)
	}

	return services, nil
}

// AddIPService 添加IP服务
func AddIPService(name, url, ipType string, priority int) (*IPService, error) {
	// 先检查URL是否已存在
	var existingID int64
	var existingName string
	err := db.QueryRow("SELECT id, name FROM ip_services WHERE url = ?", url).Scan(&existingID, &existingName)
	if err == nil {
		// URL已存在
		return nil, fmt.Errorf("该服务URL已存在（服务名: %s）", existingName)
	}

	result, err := db.Exec(
		"INSERT INTO ip_services (name, url, type, enabled, priority) VALUES (?, ?, ?, 1, ?)",
		name, url, ipType, priority,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return &IPService{
		ID:       id,
		Name:     name,
		URL:      url,
		Type:     ipType,
		Enabled:  true,
		Priority: priority,
	}, nil
}

// UpdateIPService 更新IP服务
func UpdateIPService(id int64, enabled bool, priority int) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := db.Exec("UPDATE ip_services SET enabled = ?, priority = ? WHERE id = ?", enabledInt, priority, id)
	return err
}

// DeleteIPService 删除IP服务
func DeleteIPService(id int64) error {
	_, err := db.Exec("DELETE FROM ip_services WHERE id = ?", id)
	return err
}

// SaveIPFetchLog 保存IP获取日志
func SaveIPFetchLog(log *IPFetchLog) error {
	successInt := 0
	if log.Success {
		successInt = 1
	}
	_, err := db.Exec(
		`INSERT INTO ip_fetch_logs (service_id, service_url, ip_type, success, ip, status_code, error, duration_ms) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ServiceID, log.ServiceURL, log.IPType, successInt, log.IP, log.StatusCode, log.Error, log.Duration,
	)
	return err
}

// GetIPFetchLogs 获取IP获取日志
func GetIPFetchLogs(limit int) ([]IPFetchLog, error) {
	rows, err := db.Query(
		`SELECT id, service_id, service_url, ip_type, success, ip, status_code, error, duration_ms, created_at 
		 FROM ip_fetch_logs ORDER BY created_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []IPFetchLog
	for rows.Next() {
		var log IPFetchLog
		var success int
		var ip, errMsg sql.NullString
		var statusCode sql.NullInt64
		if err := rows.Scan(&log.ID, &log.ServiceID, &log.ServiceURL, &log.IPType, &success, &ip, &statusCode, &errMsg, &log.Duration, &log.CreatedAt); err != nil {
			return nil, err
		}
		log.Success = success == 1
		log.IP = ip.String
		log.StatusCode = int(statusCode.Int64)
		log.Error = errMsg.String
		logs = append(logs, log)
	}

	return logs, nil
}

// SaveAppLog 保存应用日志
func SaveAppLog(level, message string) error {
	_, err := db.Exec("INSERT INTO app_logs (level, message) VALUES (?, ?)", level, message)
	return err
}

// GetAppLogs 获取应用日志
func GetAppLogs(limit int, level string) ([]AppLog, error) {
	query := "SELECT id, level, message, created_at FROM app_logs"
	args := []interface{}{}

	if level != "" {
		query += " WHERE level = ?"
		args = append(args, level)
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AppLog
	for rows.Next() {
		var log AppLog
		if err := rows.Scan(&log.ID, &log.Level, &log.Message, &log.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// SaveIPRecord 保存IP记录
func SaveIPRecord(ipType, ip string) error {
	_, err := db.Exec("INSERT INTO ip_records (type, ip) VALUES (?, ?)", ipType, ip)
	return err
}

// GetLatestIPRecords 获取最新的IP记录
func GetLatestIPRecords() (map[string]string, error) {
	rows, err := db.Query(`
		SELECT type, ip FROM ip_records 
		WHERE id IN (SELECT MAX(id) FROM ip_records GROUP BY type)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make(map[string]string)
	for rows.Next() {
		var ipType, ip string
		if err := rows.Scan(&ipType, &ip); err != nil {
			return nil, err
		}
		records[ipType] = ip
	}

	return records, nil
}

// GetSetting 获取配置
func GetSetting(key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSetting 设置配置
func SetSetting(key, value string) error {
	_, err := db.Exec(
		"INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

// CleanOldLogs 清理旧日志
func CleanOldLogs(retentionHours int) error {
	_, err := CleanOldLogsWithCount(retentionHours)
	return err
}

// CleanOldLogsWithCount 清理旧日志并返回删除数量
func CleanOldLogsWithCount(retentionHours int) (int64, error) {
	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour)
	cutoffStr := cutoff.Format("2006-01-02 15:04:05")

	// 清理IP获取日志
	result1, err := db.Exec("DELETE FROM ip_fetch_logs WHERE created_at < ?", cutoffStr)
	if err != nil {
		return 0, fmt.Errorf("清理IP获取日志失败: %v", err)
	}
	count1, _ := result1.RowsAffected()

	// 清理应用日志
	result2, err := db.Exec("DELETE FROM app_logs WHERE created_at < ?", cutoffStr)
	if err != nil {
		return 0, fmt.Errorf("清理应用日志失败: %v", err)
	}
	count2, _ := result2.RowsAffected()

	total := count1 + count2
	if total > 0 {
		DBLogInfo("清理旧日志完成: IP获取日志 %d 条, 应用日志 %d 条", count1, count2)
	}

	return total, nil
}

// StartLogCleanupScheduler 启动日志清理定时任务
func StartLogCleanupScheduler(retentionHours int) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		// 启动时先清理一次
		CleanOldLogs(retentionHours)

		for range ticker.C {
			CleanOldLogs(retentionHours)
		}
	}()
}

// CloseDatabase 关闭数据库
func CloseDatabase() {
	if db != nil {
		db.Close()
	}
}

// DBLogInfo 数据库日志 - 信息
func DBLogInfo(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	SaveAppLog("INFO", message)
	fmt.Printf("[%s] [INFO] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
}

// DBLogWarn 数据库日志 - 警告
func DBLogWarn(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	SaveAppLog("WARN", message)
	fmt.Printf("[%s] [WARN] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
}

// DBLogError 数据库日志 - 错误
func DBLogError(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	SaveAppLog("ERROR", message)
	fmt.Printf("[%s] [ERROR] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
}
