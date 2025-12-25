package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPInfo IP信息结构
type IPInfo struct {
	PublicIPv4  []string `json:"public_ipv4"`
	PublicIPv6  []string `json:"public_ipv6"`
	PrivateIPv4 []string `json:"private_ipv4"`
	PrivateIPv6 []string `json:"private_ipv6"`
}

// IPFetchResult IP获取结果
type IPFetchResult struct {
	Success    bool   `json:"success"`
	IP         string `json:"ip"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
	Duration   int64  `json:"duration_ms"`
}

// TestIPService 测试单个IP服务
func TestIPService(url string, ipType string) *IPFetchResult {
	result := &IPFetchResult{}
	startTime := time.Now()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	result.Duration = time.Since(startTime).Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		result.Success = false
		result.Error = fmt.Sprintf("HTTP状态码: %d", resp.StatusCode)
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("读取响应失败: %v", err)
		return result
	}

	ip := strings.TrimSpace(string(body))

	// 验证IP格式
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		result.Success = false
		result.Error = fmt.Sprintf("无效的IP格式: %s", ip)
		return result
	}

	// 验证IP类型
	if ipType == "ipv4" && parsedIP.To4() == nil {
		result.Success = false
		result.Error = fmt.Sprintf("期望IPv4但获取到IPv6: %s", ip)
		return result
	}
	if ipType == "ipv6" && parsedIP.To4() != nil {
		result.Success = false
		result.Error = fmt.Sprintf("期望IPv6但获取到IPv4: %s", ip)
		return result
	}

	result.Success = true
	result.IP = ip
	return result
}

// FetchPublicIP 获取公网IP（带重试和日志记录）
func FetchPublicIP(ipType string, maxRounds int) (string, error) {
	services, err := GetEnabledIPServices(ipType)
	if err != nil {
		return "", fmt.Errorf("获取IP服务列表失败: %v", err)
	}

	if len(services) == 0 {
		return "", fmt.Errorf("没有可用的%s服务", ipType)
	}

	// 循环尝试多轮
	for round := 0; round < maxRounds; round++ {
		for _, svc := range services {
			result := TestIPService(svc.URL, ipType)

			// 记录获取日志
			fetchLog := &IPFetchLog{
				ServiceID:  svc.ID,
				ServiceURL: svc.URL,
				IPType:     ipType,
				Success:    result.Success,
				IP:         result.IP,
				StatusCode: result.StatusCode,
				Error:      result.Error,
				Duration:   result.Duration,
			}
			SaveIPFetchLog(fetchLog)

			// 更新服务统计
			UpdateServiceStats(svc.ID, result.Success, result.IP, result.Duration)

			if result.Success {
				DBLogInfo("[%s] 从 %s 获取成功: %s (耗时: %dms)", ipType, svc.Name, result.IP, result.Duration)
				return result.IP, nil
			}

			DBLogWarn("[%s] 从 %s 获取失败: %s (耗时: %dms)", ipType, svc.Name, result.Error, result.Duration)
		}

		// 每轮之间等待一下
		if round < maxRounds-1 {
			time.Sleep(2 * time.Second)
		}
	}

	return "", fmt.Errorf("所有%s服务均获取失败", ipType)
}

// CheckNetworkConnectivity 检查网络连通性（通过阿里DNS）
func CheckNetworkConnectivity() (bool, error) {
	testURLs := []string{
		"https://223.5.5.5", // 阿里DNS
		"https://223.6.6.6", // 阿里DNS备用
		"https://1.1.1.1",   // Cloudflare DNS
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, url := range testURLs {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return true, nil
		}
	}

	// 尝试DNS解析
	_, err := net.LookupHost("www.baidu.com")
	if err == nil {
		return true, nil
	}

	return false, fmt.Errorf("网络连接失败")
}

// 断网时的占位IP
const (
	DisconnectedIPv4 = "0.0.0.0"
	DisconnectedIPv6 = "::"
)

// GetAllPublicIPs 获取所有公网IP
func GetAllPublicIPs() (ipv4, ipv6 string, networkOK bool) {
	maxRounds := 2

	// 获取IPv4
	ipv4, err4 := FetchPublicIP("ipv4", maxRounds)
	if err4 != nil {
		DBLogWarn("获取公网IPv4失败: %v", err4)
	}

	// 获取IPv6
	ipv6, err6 := FetchPublicIP("ipv6", maxRounds)
	if err6 != nil {
		DBLogWarn("获取公网IPv6失败: %v", err6)
	}

	// 判断网络状态
	if ipv4 == "" && ipv6 == "" {
		// 都获取失败，检查网络连通性
		networkOK, _ = CheckNetworkConnectivity()
		if !networkOK {
			DBLogError("网络断开，无法获取公网IP")
			ipv4 = DisconnectedIPv4
			ipv6 = DisconnectedIPv6
		}
	} else {
		networkOK = true
	}

	return ipv4, ipv6, networkOK
}

// ValidateAndCompareIPs 验证并比较IP变化
func ValidateAndCompareIPs(oldIPv4, oldIPv6, newIPv4, newIPv6 string) (changed bool, issues []string) {
	issues = []string{}

	// 检查是否断网
	if newIPv4 == DisconnectedIPv4 && newIPv6 == DisconnectedIPv6 {
		// 断网状态，不报告变化，等待网络恢复
		return false, []string{"网络断开"}
	}

	// 检查IPv4
	if oldIPv4 != "" && oldIPv4 != DisconnectedIPv4 {
		if newIPv4 == "" {
			// IPv4获取失败但IPv6成功，说明网络通，可能是服务问题
			if newIPv6 != "" && newIPv6 != DisconnectedIPv6 {
				// 检查网络连通性
				if ok, _ := CheckNetworkConnectivity(); ok {
					issues = append(issues, fmt.Sprintf("IPv4获取失败但网络正常，之前IP: %s，可能需要更换IP获取服务", oldIPv4))
				}
			}
		} else if newIPv4 != oldIPv4 {
			changed = true
			issues = append(issues, fmt.Sprintf("IPv4地址变化: %s -> %s", oldIPv4, newIPv4))
		}
	} else if newIPv4 != "" && newIPv4 != DisconnectedIPv4 {
		changed = true
		issues = append(issues, fmt.Sprintf("新增IPv4地址: %s", newIPv4))
	}

	// 检查IPv6
	if oldIPv6 != "" && oldIPv6 != DisconnectedIPv6 {
		if newIPv6 == "" {
			if newIPv4 != "" && newIPv4 != DisconnectedIPv4 {
				if ok, _ := CheckNetworkConnectivity(); ok {
					issues = append(issues, fmt.Sprintf("IPv6获取失败但网络正常，之前IP: %s，可能需要更换IP获取服务", oldIPv6))
				}
			}
		} else if newIPv6 != oldIPv6 {
			changed = true
			issues = append(issues, fmt.Sprintf("IPv6地址变化: %s -> %s", oldIPv6, newIPv6))
		}
	} else if newIPv6 != "" && newIPv6 != DisconnectedIPv6 {
		changed = true
		issues = append(issues, fmt.Sprintf("新增IPv6地址: %s", newIPv6))
	}

	return changed, issues
}

// FormatIPv6Full 将IPv6地址格式化为完整格式
func FormatIPv6Full(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

// GetLocalIPs 获取本地网卡IP
func GetLocalIPs() (privateIPv4, privateIPv6 []string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				// IPv4
				if isPrivateIP(ipnet.IP) {
					privateIPv4 = append(privateIPv4, ipnet.IP.String())
				}
			} else if ipnet.IP.To16() != nil {
				// IPv6
				if isPrivateIPv6(ipnet.IP) {
					privateIPv6 = append(privateIPv6, FormatIPv6Full(ipnet.IP))
				}
			}
		}
	}

	return
}

// isPrivateIP 判断是否为私有IPv4地址
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateIPv6 判断是否为私有IPv6地址
func isPrivateIPv6(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() {
		return true
	}

	_, uniqueLocal, _ := net.ParseCIDR("fc00::/7")
	if uniqueLocal.Contains(ip) {
		return true
	}

	return false
}

// getAllIPs 获取所有IP地址信息（使用缓存，不重新获取公网IP）
func getAllIPs() IPInfo {
	info := IPInfo{
		PublicIPv4:  []string{},
		PublicIPv6:  []string{},
		PrivateIPv4: []string{},
		PrivateIPv6: []string{},
	}

	// 从配置中读取上次保存的公网IP（缓存）
	if config.LastPublicIPv4 != "" && config.LastPublicIPv4 != DisconnectedIPv4 {
		info.PublicIPv4 = []string{config.LastPublicIPv4}
	}
	if config.LastPublicIPv6 != "" && config.LastPublicIPv6 != DisconnectedIPv6 {
		info.PublicIPv6 = []string{config.LastPublicIPv6}
	}

	// 获取本地私网IP（这个很快，每次获取也没问题）
	info.PrivateIPv4, info.PrivateIPv6 = GetLocalIPs()

	return info
}
