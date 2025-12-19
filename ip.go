package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type IPInfo struct {
	PublicIPv4  []string `json:"public_ipv4"`
	PublicIPv6  []string `json:"public_ipv6"`
	PrivateIPv4 []string `json:"private_ipv4"`
	PrivateIPv6 []string `json:"private_ipv6"`
}

// 获取所有IP地址信息
func getAllIPs() IPInfo {
	info := IPInfo{
		PublicIPv4:  []string{},
		PublicIPv6:  []string{},
		PrivateIPv4: []string{},
		PrivateIPv6: []string{},
	}

	// 获取本地网卡IP
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					// IPv4
					if isPrivateIP(ipnet.IP) {
						info.PrivateIPv4 = append(info.PrivateIPv4, ipnet.IP.String())
					}
				} else if ipnet.IP.To16() != nil {
					// IPv6 - 显示所有地址（包括完整格式）
					ipv6Str := formatIPv6Full(ipnet.IP)
					if isPrivateIPv6(ipnet.IP) {
						info.PrivateIPv6 = append(info.PrivateIPv6, ipv6Str)
					} else {
						// 公网IPv6也从本地网卡获取
						info.PublicIPv6 = append(info.PublicIPv6, ipv6Str)
					}
				}
			}
		}
	}

	// 获取本地网卡的公网IPv4
	addrs, err = net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil && !isPrivateIP(ipnet.IP) {
					// 公网IPv4
					info.PublicIPv4 = append(info.PublicIPv4, ipnet.IP.String())
				}
			}
		}
	}

	// 如果本地没有公网IPv4，尝试从外部服务获取
	if len(info.PublicIPv4) == 0 {
		if publicIPv4 := getPublicIPv4(); publicIPv4 != "" {
			info.PublicIPv4 = append(info.PublicIPv4, publicIPv4)
		}
	}

	// 如果本地没有公网IPv6，尝试从外部服务获取
	if len(info.PublicIPv6) == 0 {
		if publicIPv6 := getPublicIPv6(); publicIPv6 != "" {
			info.PublicIPv6 = append(info.PublicIPv6, formatIPv6Full(net.ParseIP(publicIPv6)))
		}
	}

	return info
}

// 将IPv6地址格式化为完整格式（不压缩零）
func formatIPv6Full(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

// 获取当前的公网IP地址列表
func getCurrentPublicIPs() []string {
	ips := []string{}
	
	if ipv4 := getPublicIPv4(); ipv4 != "" {
		ips = append(ips, ipv4)
	}
	
	if ipv6 := getPublicIPv6(); ipv6 != "" {
		ips = append(ips, ipv6)
	}
	
	return ips
}

// 获取公网IPv4地址
func getPublicIPv4() string {
	services := []string{
		"https://api.ipify.org",
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
	}

	for _, service := range services {
		if ip := fetchIP(service); ip != "" && net.ParseIP(ip).To4() != nil {
			return ip
		}
	}
	return ""
}

// 获取公网IPv6地址
func getPublicIPv6() string {
	services := []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
	}

	for _, service := range services {
		if ip := fetchIP(service); ip != "" && net.ParseIP(ip).To4() == nil {
			return ip
		}
	}
	return ""
}

// 从指定服务获取IP
func fetchIP(url string) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}

// 判断是否为私有IPv4地址
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

// 判断是否为私有IPv6地址
func isPrivateIPv6(ip net.IP) bool {
	// 链路本地地址 fe80::/10
	// 唯一本地地址 fc00::/7
	if ip.IsLinkLocalUnicast() {
		return true
	}
	
	_, uniqueLocal, _ := net.ParseCIDR("fc00::/7")
	if uniqueLocal.Contains(ip) {
		return true
	}
	
	return false
}
