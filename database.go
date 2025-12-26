package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	dbMu sync.Mutex
)

// dbExec 执行SQL语句（带锁保护）
func dbExec(query string, args ...interface{}) (sql.Result, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	return db.Exec(query, args...)
}

// dbQuery 执行查询语句（带锁保护）
func dbQuery(query string, args ...interface{}) (*sql.Rows, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	return db.Query(query, args...)
}

// dbQueryRow 执行单行查询（带锁保护）
func dbQueryRow(query string, args ...interface{}) *sql.Row {
	dbMu.Lock()
	defer dbMu.Unlock()
	return db.QueryRow(query, args...)
}

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

// AppLog 应用日志
type AppLog struct {
	ID        int64  `json:"id"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

// IPRecord IP记录（每种类型的当前IP列表，可能有多个）
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
		`CREATE INDEX IF NOT EXISTS idx_app_logs_created_at ON app_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_records_type ON ip_records(type)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_records_type_recorded_at ON ip_records(type, recorded_at)`,
	}

	for _, table := range tables {
		if _, err := dbExec(table); err != nil {
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
		dbExec(migration)
	}

	return nil
}

// initDefaultIPServices 初始化默认IP获取服务
func initDefaultIPServices() error {
	// 检查是否已有数据
	var count int
	err := dbQueryRow("SELECT COUNT(*) FROM ip_services").Scan(&count)
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
		{"AWS checkip", "https://checkip.amazonaws.com", 1},
		{"ip.sb", "https://api-ipv4.ip.sb/ip", 2},
		{"icanhazip", "https://ipv4.icanhazip.com", 3},
		{"3322.net", "https://ip.3322.net", 4},
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
		{"myexternalip", "https://myexternalip.com/raw", 5},
		{"ifconfig", "https://ifconfig.me/ip", 6},
		{"ipecho", "https://ipecho.net/plain", 7},
	}

	// 插入IPv4服务
	for _, svc := range ipv4Services {
		_, err := dbExec(
			"INSERT INTO ip_services (name, url, type, enabled, priority) VALUES (?, ?, 'ipv4', 1, ?)",
			svc.name, svc.url, svc.priority,
		)
		if err != nil {
			return err
		}
	}

	// 插入IPv6服务
	for _, svc := range ipv6Services {
		_, err := dbExec(
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

	rows, err := dbQuery(query, args...)
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
	row := dbQueryRow(query, id)

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
		// 注意: avg计算使用的是更新前的success_count,因为UPDATE中success_count已经+1
		_, err := dbExec(`
			UPDATE ip_services SET
				success_count = COALESCE(success_count, 0) + 1,
				last_success_at = ?,
				last_ip = ?,
				avg_duration_ms = CASE
					WHEN COALESCE(success_count, 0) = 0 THEN ?
					ELSE (COALESCE(avg_duration_ms, 0) * success_count + ?) / (success_count + 1)
				END
			WHERE id = ?`,
			now, ip, durationMs, durationMs, serviceID)
		return err
	} else {
		// 失败：更新失败次数、最后失败时间
		_, err := dbExec(`
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

	rows, err := dbQuery(query, args...)
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
	err := dbQueryRow("SELECT id, name FROM ip_services WHERE url = ?", url).Scan(&existingID, &existingName)
	if err == nil {
		// URL已存在
		return nil, fmt.Errorf("该服务URL已存在（服务名: %s）", existingName)
	}

	result, err := dbExec(
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
	_, err := dbExec("UPDATE ip_services SET enabled = ?, priority = ? WHERE id = ?", enabledInt, priority, id)
	return err
}

// DeleteIPService 删除IP服务
func DeleteIPService(id int64) error {
	_, err := dbExec("DELETE FROM ip_services WHERE id = ?", id)
	return err
}

// DeleteAllIPServices 删除所有IP服务
func DeleteAllIPServices() (int64, error) {
	result, err := dbExec("DELETE FROM ip_services")
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// SaveAppLog 保存应用日志
func SaveAppLog(level, message string) error {
	_, err := dbExec("INSERT INTO app_logs (level, message) VALUES (?, ?)", level, message)
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

	rows, err := dbQuery(query, args...)
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

// GetSetting 获取配置
func GetSetting(key string) (string, error) {
	var value string
	err := dbQueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSetting 设置配置
func SetSetting(key, value string) error {
	_, err := dbExec(
		"INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

// ==================== 邮件配置管理 ====================

// EmailConfig 邮件配置
type EmailConfig struct {
	SenderEmail    string   `json:"sender_email"`
	SenderPassword string   `json:"sender_password"`
	SMTPServer     string   `json:"smtp_server"`
	SMTPPort       int      `json:"smtp_port"`
	Recipients     []string `json:"recipients"`
}

// SaveEmailConfig 保存邮件配置
func SaveEmailConfig(cfg *EmailConfig) error {
	// 保存简单字段
	SetSetting("sender_email", cfg.SenderEmail)
	SetSetting("sender_password", cfg.SenderPassword)
	SetSetting("smtp_server", cfg.SMTPServer)
	SetSetting("smtp_port", fmt.Sprintf("%d", cfg.SMTPPort))

	// 保存收件人列表(JSON格式)
	recipientsJSON, err := jsonMarshal(cfg.Recipients)
	if err != nil {
		return err
	}
	SetSetting("recipients", string(recipientsJSON))

	return nil
}

// GetEmailConfig 获取邮件配置
func GetEmailConfig() (*EmailConfig, error) {
	cfg := &EmailConfig{
		SMTPPort: 587, // 默认端口
	}

	// 读取简单字段
	cfg.SenderEmail, _ = GetSetting("sender_email")
	cfg.SenderPassword, _ = GetSetting("sender_password")
	cfg.SMTPServer, _ = GetSetting("smtp_server")

	if portStr, err := GetSetting("smtp_port"); err == nil && portStr != "" {
		if port, err := parseInt(portStr); err == nil {
			cfg.SMTPPort = port
		}
	}

	// 读取收件人列表
	recipientsJSON, err := GetSetting("recipients")
	if err == nil && recipientsJSON != "" {
		recipients, err := jsonUnmarshal(recipientsJSON)
		if err == nil {
			cfg.Recipients = recipients
		}
	}

	return cfg, nil
}

// ==================== 监控配置管理 ====================

// MonitorConfig 监控配置
type MonitorConfig struct {
	AutoMode          bool     `json:"auto_mode"`
	IntervalMinutes   int      `json:"interval_minutes"`
	MonitorTypes      []string `json:"monitor_types"`
	LogRetentionHours int      `json:"log_retention_hours"`
}

// SaveMonitorConfig 保存监控配置
func SaveMonitorConfig(cfg *MonitorConfig) error {
	SetSetting("auto_mode", boolToString(cfg.AutoMode))
	SetSetting("interval_minutes", fmt.Sprintf("%d", cfg.IntervalMinutes))
	SetSetting("log_retention_hours", fmt.Sprintf("%d", cfg.LogRetentionHours))

	// 保存监控类型列表(JSON格式)
	typesJSON, err := jsonMarshal(cfg.MonitorTypes)
	if err != nil {
		return err
	}
	SetSetting("monitor_types", string(typesJSON))

	return nil
}

// GetMonitorConfig 获取监控配置
func GetMonitorConfig() (*MonitorConfig, error) {
	cfg := &MonitorConfig{
		AutoMode:          false,
		IntervalMinutes:   30,      // 默认30分钟
		MonitorTypes:      []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"},
		LogRetentionHours: 72,      // 默认72小时
	}

	// 读取自动模式
	if autoModeStr, err := GetSetting("auto_mode"); err == nil && autoModeStr != "" {
		cfg.AutoMode = stringToBool(autoModeStr)
	}

	// 读取间隔
	if intervalStr, err := GetSetting("interval_minutes"); err == nil && intervalStr != "" {
		if interval, err := parseInt(intervalStr); err == nil && interval > 0 {
			cfg.IntervalMinutes = interval
		}
	}

	// 读取日志保留时间
	if retentionStr, err := GetSetting("log_retention_hours"); err == nil && retentionStr != "" {
		if retention, err := parseInt(retentionStr); err == nil && retention > 0 {
			cfg.LogRetentionHours = retention
		}
	}

	// 读取监控类型列表
	typesJSON, err := GetSetting("monitor_types")
	if err == nil && typesJSON != "" {
		types, err := jsonUnmarshal(typesJSON)
		if err == nil && len(types) > 0 {
			cfg.MonitorTypes = types
		}
	}

	return cfg, nil
}

// ==================== 初始化默认配置 ====================

// InitDefaultConfig 初始化默认配置(仅当数据库中没有配置时)
func InitDefaultConfig() error {
	// 检查是否已有配置
	if val, _ := GetSetting("config_initialized"); val == "1" {
		return nil // 已初始化
	}

	// 保存默认监控配置
	defaultMonitor := &MonitorConfig{
		AutoMode:          false,
		IntervalMinutes:   30,
		MonitorTypes:      []string{"public_ipv4", "public_ipv6", "private_ipv4", "private_ipv6"},
		LogRetentionHours: 72,
	}
	if err := SaveMonitorConfig(defaultMonitor); err != nil {
		return err
	}

	// 标记已初始化
	SetSetting("config_initialized", "1")

	return nil
}

// ==================== 辅助函数 ====================

// jsonMarshal 简单的JSON序列化
func jsonMarshal(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	return data, err
}

// jsonUnmarshal 反序列化字符串数组
func jsonUnmarshal(s string) ([]string, error) {
	var result []string
	err := json.Unmarshal([]byte(s), &result)
	return result, err
}

// parseInt 解析整数
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

// boolToString 布尔转字符串
func boolToString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// stringToBool 字符串转布尔
func stringToBool(s string) bool {
	return s == "1" || s == "true"
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

	// 清理应用日志
	result, err := dbExec("DELETE FROM app_logs WHERE created_at < ?", cutoffStr)
	if err != nil {
		return 0, fmt.Errorf("清理应用日志失败: %v", err)
	}
	count, _ := result.RowsAffected()

	return count, nil
}

// StartLogCleanupScheduler 启动日志清理定时任务
func StartLogCleanupScheduler(retentionHours int) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		// 启动时先清理一次
		deleted, _ := CleanOldLogsWithCount(retentionHours)
		if deleted > 0 {
			DBLogInfo("定时清理旧日志完成: 删除了 %d 条记录", deleted)
		}

		for {
			select {
			case <-ticker.C:
				deleted, _ := CleanOldLogsWithCount(retentionHours)
				if deleted > 0 {
					DBLogInfo("定时清理旧日志完成: 删除了 %d 条记录", deleted)
				}
			case <-logCleanupStop:
				DBLogInfo("日志清理scheduler已停止")
				return
			}
		}
	}()
}

// StopLogCleanupScheduler 停止日志清理定时任务
func StopLogCleanupScheduler() {
	if logCleanupStop != nil {
		close(logCleanupStop)
		logCleanupStop = nil
	}
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
}

// DBLogWarn 数据库日志 - 警告
func DBLogWarn(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	SaveAppLog("WARN", message)
}

// DBLogError 数据库日志 - 错误
func DBLogError(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	SaveAppLog("ERROR", message)
}

// ==================== 最后IP记录管理 ====================

// SaveLastIPs 保存指定类型的所有IP（删除旧记录后插入新记录）
func SaveLastIPs(ipType string, ips []string) error {
	// 先删除该类型的所有旧记录
	_, err := dbExec("DELETE FROM ip_records WHERE type = ?", ipType)
	if err != nil {
		return err
	}

	// 插入新记录
	for _, ip := range ips {
		_, err := dbExec(
			"INSERT INTO ip_records (type, ip) VALUES (?, ?)",
			ipType, ip,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// SaveLastIP 保存最后一次的IP（用于对比，兼容旧代码）
func SaveLastIP(ipType, ip string) error {
	return SaveLastIPs(ipType, []string{ip})
}

// GetLastIP 获取最后一次的IP
func GetLastIP(ipType string) (string, error) {
	var ip string
	err := dbQueryRow(
		"SELECT ip FROM ip_records WHERE type = ? ORDER BY recorded_at DESC LIMIT 1",
		ipType,
	).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil // 没有记录，返回空字符串
	}
	return ip, err
}

// GetAllLastIPs 获取所有类型的当前IP列表（每种类型可能有多个IP）
func GetAllLastIPs() (map[string][]string, error) {
	rows, err := dbQuery(`
		SELECT type, ip FROM ip_records
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var ipType, ip string
		if err := rows.Scan(&ipType, &ip); err != nil {
			return nil, err
		}
		result[ipType] = append(result[ipType], ip)
	}

	return result, nil
}

// GetAllLastIPsAsMap 获取所有类型的当前IP（返回单值map，用于兼容旧代码）
func GetAllLastIPsAsMap() (map[string]string, error) {
	rows, err := dbQuery(`
		SELECT type, ip FROM ip_records
		WHERE id IN (
			SELECT MAX(id) FROM ip_records GROUP BY type
		)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var ipType, ip string
		if err := rows.Scan(&ipType, &ip); err != nil {
			return nil, err
		}
		result[ipType] = ip
	}

	return result, nil
}

// DeleteLastIP 删除指定类型的最后IP
func DeleteLastIP(ipType string) error {
	_, err := dbExec("DELETE FROM ip_records WHERE type = ?", ipType)
	return err
}
