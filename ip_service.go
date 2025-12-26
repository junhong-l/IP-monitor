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

	// 设置整体超时时间(30秒)
	timeout := time.After(30 * time.Second)
	round := 0

	// 循环尝试多轮,使用带超时的select
	for {
		select {
		case <-timeout:
			// 超时,立即返回
			return "", fmt.Errorf("获取%s超时(30秒)", ipType)
		default:
			// 继续尝试
		}

		// 检查是否已达到最大轮数
		if round >= maxRounds {
			return "", fmt.Errorf("所有%s服务均获取失败", ipType)
		}

		// 尝试当前轮的所有服务
		for _, svc := range services {
			result := TestIPService(svc.URL, ipType)

			// 更新服务统计
			UpdateServiceStats(svc.ID, result.Success, result.IP, result.Duration)

			if result.Success {
				finalIP := result.IP
				// 对于IPv6，尝试选择更好的本地公网地址（优先EUI-64格式）
				if ipType == "ipv6" {
					finalIP = SelectBestPublicIPv6(result.IP)
				}
				DBLogInfo("[%s] 从 %s 获取成功: %s (耗时: %dms)", ipType, svc.Name, finalIP, result.Duration)
				return finalIP, nil
			}

			DBLogWarn("[%s] 从 %s 获取失败: %s (耗时: %dms)", ipType, svc.Name, result.Error, result.Duration)
		}

		round++

		// 每轮之间等待一下
		if round < maxRounds {
			time.Sleep(2 * time.Second)
		}
	}
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
// 如果IP无效,返回空字符串。调用方应该检查返回值。
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
					formatted := FormatIPv6Full(ipnet.IP)
					if formatted != "" {
						privateIPv6 = append(privateIPv6, formatted)
					}
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

// isPublicIPv6 判断是否为公网IPv6地址
func isPublicIPv6(ip net.IP) bool {
	// 排除环回地址
	if ip.IsLoopback() {
		return false
	}

	// 排除链路本地地址 (fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return false
	}

	// 排除唯一本地地址 (fc00::/7, 包括 fd00::/8)
	_, uniqueLocal, _ := net.ParseCIDR("fc00::/7")
	if uniqueLocal.Contains(ip) {
		return false
	}

	// 排除组播地址 (ff00::/8)
	if ip.IsMulticast() {
		return false
	}

	// 排除未指定地址 (::)
	if ip.IsUnspecified() {
		return false
	}

	// 排除文档地址 (2001:db8::/32)
	_, doc, _ := net.ParseCIDR("2001:db8::/32")
	if doc.Contains(ip) {
		return false
	}

	return true
}

// isEUI64Address 判断是否为EUI-64格式的IPv6地址（基于MAC地址生成，更稳定）
// EUI-64地址的特征：第11和12字节是 ff:fe
func isEUI64Address(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	// 检查接口标识符部分是否包含 ff:fe（EUI-64特征）
	return ip16[11] == 0xff && ip16[12] == 0xfe
}

// isSLAACAddress 判断是否为SLAAC生成的地址（包括EUI-64和隐私扩展）
// SLAAC地址的前64位是网络前缀，后64位是接口标识符
func isSLAACAddress(ip net.IP) bool {
	// 公网IPv6地址通常都是SLAAC或DHCPv6生成的
	return isPublicIPv6(ip)
}

// GetLocalPublicIPv6 获取本地公网IPv6地址
// 优先返回最长的地址（接口标识符部分非零位最多的），通常是可被外部访问的地址
func GetLocalPublicIPv6() []string {
	var publicIPv6 []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return publicIPv6
	}

	for _, iface := range interfaces {
		// 跳过未启用的接口和环回接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP
			// 只处理IPv6
			if ip.To4() != nil {
				continue
			}

			if isPublicIPv6(ip) {
				fullIP := FormatIPv6Full(ip)
				if fullIP != "" {
					publicIPv6 = append(publicIPv6, fullIP)
				}
			}
		}
	}

	// 按接口标识符部分的非零字节数排序，优先选择"更完整"的地址
	// 像 2408:8266:bb01:176b:3cb7:e39f:eb1c:a459 会排在 2408:8266:bb01:176b::8af 前面
	if len(publicIPv6) > 1 {
		sortIPv6ByComplexity(publicIPv6)
	}

	return publicIPv6
}

// sortIPv6ByComplexity 按接口标识符的复杂度排序（非零字节越多越靠前）
func sortIPv6ByComplexity(ips []string) {
	// 简单冒泡排序
	for i := 0; i < len(ips)-1; i++ {
		for j := i + 1; j < len(ips); j++ {
			if countNonZeroBytes(ips[j]) > countNonZeroBytes(ips[i]) {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}
}

// countNonZeroBytes 计算IPv6地址接口标识符部分（后64位）的非零字节数
func countNonZeroBytes(ipStr string) int {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0
	}
	// 只计算后8字节（接口标识符部分）
	count := 0
	for i := 8; i < 16; i++ {
		if ip16[i] != 0 {
			count++
		}
	}
	return count
}

// SelectBestPublicIPv6 选择最佳的公网IPv6地址
// 优先使用本地网卡获取的公网IPv6地址（选择接口标识符最完整的）
// 如果外部API返回的是公网地址，查找本地同前缀的更完整地址
func SelectBestPublicIPv6(externalIP string) string {
	if externalIP == "" {
		return ""
	}

	extIP := net.ParseIP(externalIP)
	if extIP == nil {
		return externalIP
	}

	// 检查外部返回的IP是否是公网地址
	if !isPublicIPv6(extIP) {
		// 如果外部返回的不是公网地址，直接返回
		return externalIP
	}

	// 获取本地公网IPv6地址列表（已按复杂度排序，最完整的在前面）
	localPublicIPs := GetLocalPublicIPv6()
	if len(localPublicIPs) == 0 {
		return externalIP
	}

	// 获取外部IP的前缀（前64位）
	extIP16 := extIP.To16()
	if extIP16 == nil {
		return externalIP
	}
	extPrefix := extIP16[:8]

	// 查找同前缀的本地地址，优先使用最完整的（列表已排序）
	for _, localIPStr := range localPublicIPs {
		localIP := net.ParseIP(localIPStr)
		if localIP == nil {
			continue
		}

		localIP16 := localIP.To16()
		if localIP16 == nil {
			continue
		}

		// 检查前缀是否相同（前64位）
		localPrefix := localIP16[:8]
		prefixMatch := true
		for i := 0; i < 8; i++ {
			if extPrefix[i] != localPrefix[i] {
				prefixMatch = false
				break
			}
		}

		if prefixMatch {
			// 找到同前缀的地址，检查是否比外部获取的更完整
			extComplexity := countNonZeroBytes(externalIP)
			localComplexity := countNonZeroBytes(localIPStr)
			
			if localComplexity > extComplexity {
				DBLogInfo("[IPv6] 使用本地更完整的地址替代外部获取的地址: %s -> %s", externalIP, localIPStr)
				return localIPStr
			}
			// 如果复杂度相同或外部更完整，使用外部的
			break
		}
	}

	return externalIP
}

// getAllIPs 获取所有IP地址信息（从数据库读取最后保存的IP）
func getAllIPs() IPInfo {
	info := IPInfo{
		PublicIPv4:  []string{},
		PublicIPv6:  []string{},
		PrivateIPv4: []string{},
		PrivateIPv6: []string{},
	}

	// 从数据库读取上次保存的公网IP
	lastIPs, err := GetAllLastIPs()
	if err == nil {
		// 根据监控类型读取
		if shouldMonitor("public_ipv4") {
			if ips, ok := lastIPs["public_ipv4"]; ok && len(ips) > 0 {
				// 过滤掉断网占位符
				validIPs := []string{}
				for _, ip := range ips {
					if ip != "" && ip != DisconnectedIPv4 {
						validIPs = append(validIPs, ip)
					}
				}
				if len(validIPs) > 0 {
					info.PublicIPv4 = validIPs
				}
			}
		}
		if shouldMonitor("public_ipv6") {
			if ips, ok := lastIPs["public_ipv6"]; ok && len(ips) > 0 {
				// 过滤掉断网占位符
				validIPs := []string{}
				for _, ip := range ips {
					if ip != "" && ip != DisconnectedIPv6 {
						validIPs = append(validIPs, ip)
					}
				}
				if len(validIPs) > 0 {
					info.PublicIPv6 = validIPs
				}
			}
		}
		if shouldMonitor("private_ipv4") {
			if ips, ok := lastIPs["private_ipv4"]; ok && len(ips) > 0 {
				info.PrivateIPv4 = ips
			}
		}
		if shouldMonitor("private_ipv6") {
			if ips, ok := lastIPs["private_ipv6"]; ok && len(ips) > 0 {
				info.PrivateIPv6 = ips
			}
		}
	}

	// 如果数据库中没有公网IP，则实时获取私网IP
	if len(info.PrivateIPv4) == 0 || len(info.PrivateIPv6) == 0 {
		privateIPv4, privateIPv6 := GetLocalIPs()
		if len(info.PrivateIPv4) == 0 {
			info.PrivateIPv4 = privateIPv4
		}
		if len(info.PrivateIPv6) == 0 {
			info.PrivateIPv6 = privateIPv6
		}
	}

	return info
}
