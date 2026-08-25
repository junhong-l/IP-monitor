package main

import (
	"crypto/tls"
    "encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// 发送IP变化通知邮件
func sendIPChangeNotification(oldIPs, newIPs []string) error {
	subject := "IP地址变更通知"
	
	oldIPsStr := "无"
	if len(oldIPs) > 0 {
		oldIPsStr = strings.Join(oldIPs, ", ")
	}
	
	newIPsStr := strings.Join(newIPs, ", ")
	
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; background-color: #f5f7fa;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="background-color: #f5f7fa; padding: 30px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
                    <!-- 头部 -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">
                                🌐 IP地址变更通知
                            </h1>
                            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 14px;">
                                您的公网IP地址已发生变化
                            </p>
                        </td>
                    </tr>
                    
                    <!-- 内容区域 -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <!-- 变更前 -->
                            <table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #ff6b6b 0%%, #ee5a5a 100%%); padding: 20px; border-radius: 12px;">
                                        <p style="color: rgba(255,255,255,0.9); margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; letter-spacing: 1px;">
                                            ⬅️ 变更前
                                        </p>
                                        <p style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 600; font-family: 'Courier New', monospace;">
                                            %s
                                        </p>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- 箭头 -->
                            <table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
                                <tr>
                                    <td align="center" style="padding: 10px;">
                                        <span style="font-size: 30px;">⬇️</span>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- 变更后 -->
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #56ab2f 0%%, #a8e063 100%%); padding: 20px; border-radius: 12px;">
                                        <p style="color: rgba(255,255,255,0.9); margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; letter-spacing: 1px;">
                                            ➡️ 变更后（当前）
                                        </p>
                                        <p style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 600; font-family: 'Courier New', monospace;">
                                            %s
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- 底部 -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #e9ecef;">
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="color: #6c757d; font-size: 13px;">
                                        <p style="margin: 0 0 5px 0;">📧 此邮件由 <strong>IP地址监控系统</strong> 自动发送</p>
                                        <p style="margin: 0;">🕐 检测时间: %s</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, oldIPsStr, newIPsStr, getCurrentTime())

	return sendEmail(subject, body)
}

// 检查某个IP类型是否发生了变化
func isTypeChanged(changes []IPChange, typeName string) bool {
	for _, c := range changes {
		if c.Type == typeName {
			return true
		}
	}
	return false
}

// 发送所有IP变化通知邮件（公网+私网）
func sendAllIPChangeNotification(oldIPs, newIPs *IPInfo, changes []IPChange) error {
	subject := "IP地址变更通知"
	
	// 获取变化的类型名称
	changeTypes := []string{}
	for _, c := range changes {
		changeTypes = append(changeTypes, c.Type)
	}
	changeTypesStr := strings.Join(changeTypes, "、")
	
	// 根据是否变化决定颜色（新IP部分：变化的用黄色高亮，旧IP部分：变化的用红色删除线）
	newPublicIPv4Style := "color: #fff;"
	newPublicIPv6Style := "color: #fff;"
	newPrivateIPv4Style := "color: #fff;"
	newPrivateIPv6Style := "color: #fff;"
	oldPublicIPv4Style := "color: #fff; font-weight: 500;"
	oldPublicIPv6Style := "color: #fff; font-weight: 500;"
	oldPrivateIPv4Style := "color: #fff; font-weight: 500;"
	oldPrivateIPv6Style := "color: #fff; font-weight: 500;"
	
	if isTypeChanged(changes, "公网IPv4") {
		newPublicIPv4Style = "color: #ffeb3b; font-weight: bold;"
		oldPublicIPv4Style = "color: #dc3545; text-decoration: line-through;"
	}
	if isTypeChanged(changes, "公网IPv6") {
		newPublicIPv6Style = "color: #ffeb3b; font-weight: bold;"
		oldPublicIPv6Style = "color: #dc3545; text-decoration: line-through;"
	}
	if isTypeChanged(changes, "私网IPv4") {
		newPrivateIPv4Style = "color: #ffeb3b; font-weight: bold;"
		oldPrivateIPv4Style = "color: #dc3545; text-decoration: line-through;"
	}
	if isTypeChanged(changes, "私网IPv6") {
		newPrivateIPv6Style = "color: #ffeb3b; font-weight: bold;"
		oldPrivateIPv6Style = "color: #dc3545; text-decoration: line-through;"
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; background-color: #f5f7fa;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="background-color: #f5f7fa; padding: 30px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
                    <!-- 头部 -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">
                                🌐 IP地址变更通知
                            </h1>
                            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 14px;">
                                检测到变化: %s
                            </p>
                        </td>
                    </tr>
                    
                    <!-- 当前IP（新） -->
                    <tr>
                        <td style="padding: 30px 30px 15px 30px;">
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #28a745 0%%, #20c997 100%%); padding: 20px; border-radius: 12px;">
                                        <h3 style="color: #fff; margin: 0 0 15px 0; font-size: 17px; font-weight: 600;">✅ 当前IP地址（新）</h3>
                                        <table width="100%%" cellpadding="10" cellspacing="0">
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; width: 110px; font-weight: 500;">🌍 公网IPv4</td>
                                                <td style="%s font-size: 15px; font-family: 'Courier New', 'Consolas', monospace;">%s</td>
                                            </tr>
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; font-weight: 500;">🌐 公网IPv6</td>
                                                <td style="%s font-size: 13px; font-family: 'Courier New', 'Consolas', monospace; word-break: break-all;">%s</td>
                                            </tr>
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; font-weight: 500;">🏠 私网IPv4</td>
                                                <td style="%s font-size: 15px; font-family: 'Courier New', 'Consolas', monospace;">%s</td>
                                            </tr>
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; font-weight: 500;">🏠 私网IPv6</td>
                                                <td style="%s font-size: 13px; font-family: 'Courier New', 'Consolas', monospace; word-break: break-all;">%s</td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- 旧IP -->
                    <tr>
                        <td style="padding: 15px 30px 30px 30px;">
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #dc3545 0%%, #c82333 100%%); padding: 20px; border-radius: 12px;">
                                        <h3 style="color: #fff; margin: 0 0 15px 0; font-size: 17px; font-weight: 600;">📋 变更前IP地址（旧）</h3>
                                        <table width="100%%" cellpadding="10" cellspacing="0">
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; width: 110px; font-weight: 500;">🌍 公网IPv4</td>
                                                <td style="%s font-size: 15px; font-family: 'Courier New', 'Consolas', monospace;">%s</td>
                                            </tr>
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; font-weight: 500;">🌐 公网IPv6</td>
                                                <td style="%s font-size: 13px; font-family: 'Courier New', 'Consolas', monospace; word-break: break-all;">%s</td>
                                            </tr>
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; font-weight: 500;">🏠 私网IPv4</td>
                                                <td style="%s font-size: 15px; font-family: 'Courier New', 'Consolas', monospace;">%s</td>
                                            </tr>
                                            <tr>
                                                <td style="color: rgba(255,255,255,0.9); font-size: 14px; font-weight: 500;">🏠 私网IPv6</td>
                                                <td style="%s font-size: 13px; font-family: 'Courier New', 'Consolas', monospace; word-break: break-all;">%s</td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- 底部 -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #e9ecef;">
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="color: #6c757d; font-size: 13px;">
                                        <p style="margin: 0 0 5px 0;">📧 此邮件由 <strong>IP地址监控系统</strong> 自动发送</p>
                                        <p style="margin: 0;">🕐 检测时间: %s</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`,
		changeTypesStr,
		newPublicIPv4Style, getIPListStr(newIPs.PublicIPv4),
		newPublicIPv6Style, getIPListStr(newIPs.PublicIPv6),
		newPrivateIPv4Style, getIPListStr(newIPs.PrivateIPv4),
		newPrivateIPv6Style, getIPListStr(newIPs.PrivateIPv6),
		oldPublicIPv4Style, getIPListStr(oldIPs.PublicIPv4),
		oldPublicIPv6Style, getIPListStr(oldIPs.PublicIPv6),
		oldPrivateIPv4Style, getIPListStr(oldIPs.PrivateIPv4),
		oldPrivateIPv6Style, getIPListStr(oldIPs.PrivateIPv6),
		getCurrentTime())

	return sendEmail(subject, body)
}

// 获取IP列表字符串（每个IP一行，带复制提示）
func getIPListStr(ips []string) string {
	if len(ips) == 0 {
		return "<span style=\"color: #ffffff; font-weight: bold; font-size: 15px;\">无</span>"
	}
	var result []string
	for _, ip := range ips {
		result = append(result, fmt.Sprintf(
			"<div style=\"margin: 6px 0; padding: 10px 12px; background: rgba(255,255,255,0.25); border-radius: 6px; font-family: 'Courier New', 'Consolas', monospace; font-size: 15px; font-weight: 600; line-height: 1.4;\">"+
				"<span style=\"color: #ffffff;\">%s</span>"+
				"<span style=\"float: right; opacity: 0.7; font-size: 12px; color: #ffffff;\">📋</span>"+
				"<div style=\"clear: both;\"></div>"+
			"</div>",
			ip,
		))
	}
	return strings.Join(result, "")
}

// 发送测试邮件
func sendTestEmail() error {
	subject := "测试邮件 - IP地址监控系统"
	
	allIPs := getAllIPs()
	
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; background-color: #f5f7fa;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="background-color: #f5f7fa; padding: 30px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
                    <!-- 头部 -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #11998e 0%%, #38ef7d 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">
                                ✅ 邮件配置测试成功
                            </h1>
                            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 14px;">
                                您的邮件服务已正确配置
                            </p>
                        </td>
                    </tr>
                    
                    <!-- 内容区域 -->
                    <tr>
                        <td style="padding: 30px;">
                            <p style="color: #495057; font-size: 15px; line-height: 1.6; margin: 0 0 25px 0;">
                                🎉 恭喜！这是一封测试邮件，说明您的邮件配置已经正确设置。以下是当前服务器的IP地址信息：
                            </p>
                            
                            <!-- IP信息卡片 -->
                            <table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom: 15px;">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 15px 20px; border-radius: 10px;">
                                        <table width="100%%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td width="30" style="vertical-align: top;">
                                                    <span style="font-size: 20px;">🌍</span>
                                                </td>
                                                <td>
                                                    <p style="color: rgba(255,255,255,0.8); margin: 0 0 5px 0; font-size: 12px;">公网 IPv4</p>
                                                    <p style="color: #ffffff; margin: 0; font-size: 16px; font-weight: 600; font-family: 'Courier New', monospace;">%s</p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom: 15px;">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); padding: 15px 20px; border-radius: 10px;">
                                        <table width="100%%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td width="30" style="vertical-align: top;">
                                                    <span style="font-size: 20px;">🌐</span>
                                                </td>
                                                <td>
                                                    <p style="color: rgba(255,255,255,0.8); margin: 0 0 5px 0; font-size: 12px;">公网 IPv6</p>
                                                    <p style="color: #ffffff; margin: 0; font-size: 14px; font-weight: 600; font-family: 'Courier New', monospace; word-break: break-all;">%s</p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom: 15px;">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #4facfe 0%%, #00f2fe 100%%); padding: 15px 20px; border-radius: 10px;">
                                        <table width="100%%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td width="30" style="vertical-align: top;">
                                                    <span style="font-size: 20px;">🏠</span>
                                                </td>
                                                <td>
                                                    <p style="color: rgba(255,255,255,0.8); margin: 0 0 5px 0; font-size: 12px;">私有 IPv4</p>
                                                    <p style="color: #ffffff; margin: 0; font-size: 16px; font-weight: 600; font-family: 'Courier New', monospace;">%s</p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #fa709a 0%%, #fee140 100%%); padding: 15px 20px; border-radius: 10px;">
                                        <table width="100%%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td width="30" style="vertical-align: top;">
                                                    <span style="font-size: 20px;">🔗</span>
                                                </td>
                                                <td>
                                                    <p style="color: rgba(255,255,255,0.8); margin: 0 0 5px 0; font-size: 12px;">私有 IPv6</p>
                                                    <p style="color: #ffffff; margin: 0; font-size: 14px; font-weight: 600; font-family: 'Courier New', monospace; word-break: break-all;">%s</p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- 底部 -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #e9ecef;">
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="color: #6c757d; font-size: 13px;">
                                        <p style="margin: 0 0 5px 0;">📧 此邮件由 <strong>IP地址监控系统</strong> 自动发送</p>
                                        <p style="margin: 0;">🕐 测试时间: %s</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
                
                <!-- 底部提示 -->
                <table width="600" cellpadding="0" cellspacing="0" style="margin-top: 20px;">
                    <tr>
                        <td align="center" style="color: #adb5bd; font-size: 12px;">
                            <p style="margin: 0;">当公网IP发生变化时，您将收到邮件通知</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, 
	formatIPList(allIPs.PublicIPv4),
	formatIPList(allIPs.PublicIPv6),
	formatIPList(allIPs.PrivateIPv4),
	formatIPList(allIPs.PrivateIPv6),
	getCurrentTime())

	return sendEmail(subject, body)
}

// 发送邮件的通用函数
func sendEmail(subject, body string) error {
	// 从数据库读取邮件配置
	emailCfg, err := GetEmailConfig()
	if err != nil {
		return fmt.Errorf("读取邮件配置失败: %v", err)
	}

	from := emailCfg.SenderEmail
	password := emailCfg.SenderPassword
	smtpServer := emailCfg.SMTPServer
	smtpPort := emailCfg.SMTPPort
	to := emailCfg.Recipients

	// 验证必要字段
    if from == "" || password == "" || len(to) == 0 {
        return fmt.Errorf("邮件配置不完整: 发件人或密码或收件人为空")
    }

    message := buildEmailMessage(from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", smtpServer, smtpPort)

	// 根据端口选择不同的发送方式
	if smtpPort == 465 {
		// SSL方式
		return sendMailSSL(addr, from, password, smtpServer, to, []byte(message))
	} else {
		// TLS方式 (587端口等)
		return sendMailTLS(addr, from, password, smtpServer, to, []byte(message))
	}
}

// buildEmailMessage 构建符合 SMTP 行长度要求的 MIME 邮件。
func buildEmailMessage(from string, to []string, subject, body string) string {
	return fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: =?UTF-8?B?%s?=\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"\r\n%s",
		from,
		foldAddressHeader(to),
		base64Encode(subject),
		encodeBase64Body(body),
	)
}

// foldAddressHeader 以空白开头的续行折叠 To 头，避免其单行超出 SMTP 限制。
func foldAddressHeader(addresses []string) string {
	const maxRecommendedLineLength = 78
	const headerPrefixLength = len("To: ")

	var builder strings.Builder
	lineLength := headerPrefixLength
	for i, address := range addresses {
		if i == 0 {
			builder.WriteString(address)
			lineLength += len(address)
			continue
		}

		if lineLength+len(", ")+len(address) > maxRecommendedLineLength {
			builder.WriteString(",\r\n ")
			builder.WriteString(address)
			lineLength = 1 + len(address)
			continue
		}

		builder.WriteString(", ")
		builder.WriteString(address)
		lineLength += len(", ") + len(address)
	}

	return builder.String()
}

// encodeBase64Body 使用每行 76 字符的 Base64 编码，避免 HTML 或 IPv6 内容产生超长 SMTP 数据行。
func encodeBase64Body(body string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	if encoded == "" {
		return ""
	}

	const maxLineLength = 76
	var builder strings.Builder
	for len(encoded) > maxLineLength {
		builder.WriteString(encoded[:maxLineLength])
		builder.WriteString("\r\n")
		encoded = encoded[maxLineLength:]
	}
	builder.WriteString(encoded)
	builder.WriteString("\r\n")

	return builder.String()
}

// 使用TLS发送邮件（端口587，STARTTLS方式）
func sendMailTLS(addr, from, password, smtpServer string, to []string, message []byte) error {
	DBLogInfo("尝试TLS方式发送邮件到 %s", addr)
	
	// 先建立普通连接
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpServer)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Close()

	// 发送STARTTLS命令
	tlsConfig := &tls.Config{
		ServerName: smtpServer,
	}
	if err = client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("STARTTLS失败: %v", err)
	}

	// 认证
	auth := smtp.PlainAuth("", from, password, smtpServer)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("认证失败: %v", err)
	}

	// 设置发件人
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	for _, recipient := range to {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("获取写入器失败: %v", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("关闭写入器失败: %v", err)
	}

	DBLogInfo("TLS邮件发送成功")
	client.Quit()
	return nil
}

// 使用SSL发送邮件（端口465）
func sendMailSSL(addr, from, password, smtpServer string, to []string, message []byte) error {
	DBLogInfo("尝试SSL方式发送邮件到 %s", addr)
	
	// 建立SSL连接
	tlsConfig := &tls.Config{
		ServerName: smtpServer,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("SSL连接失败: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpServer)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Close()

	// 认证
	auth := smtp.PlainAuth("", from, password, smtpServer)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("认证失败: %v", err)
	}

	// 设置发件人
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	for _, recipient := range to {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("获取写入器失败: %v", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("关闭写入器失败: %v", err)
	}

	DBLogInfo("SSL邮件发送成功")
	// 邮件已成功发送，忽略Quit的错误
	client.Quit()
	return nil
}

// Base64编码（用于邮件主题）
func base64Encode(s string) string {
	return base64EncodeBytes([]byte(s))
}

func base64EncodeBytes(b []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		remaining := len(b) - i
		if remaining >= 3 {
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			result = append(result, base64Table[n>>18&0x3F], base64Table[n>>12&0x3F], base64Table[n>>6&0x3F], base64Table[n&0x3F])
		} else if remaining == 2 {
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8
			result = append(result, base64Table[n>>18&0x3F], base64Table[n>>12&0x3F], base64Table[n>>6&0x3F], '=')
		} else {
			n = uint32(b[i]) << 16
			result = append(result, base64Table[n>>18&0x3F], base64Table[n>>12&0x3F], '=', '=')
		}
	}
	return string(result)
}

// 格式化IP列表用于显示（每个IP一行，带背景样式）
func formatIPList(ips []string) string {
	if len(ips) == 0 {
		return "<span style=\"color: rgba(255,255,255,0.5);\">无</span>"
	}
	var result []string
	for _, ip := range ips {
		result = append(result, fmt.Sprintf(
			"<div style=\"margin: 4px 0; padding: 6px 10px; background: rgba(255,255,255,0.15); border-radius: 4px; font-family: 'Courier New', monospace;\">"+
				"%s"+
				"<span style=\"float: right; opacity: 0.6; font-size: 11px; color: rgba(255,255,255,0.7);\">📋</span>"+
			"</div>",
			ip,
		))
	}
	return strings.Join(result, "")
}

// 获取当前时间字符串
func getCurrentTime() string {
	return fmt.Sprintf("%s", time.Now().Format("2006-01-02 15:04:05"))
}

// 发送IP获取警告邮件
func sendIPFetchWarningEmail(warningType, oldIPv4, oldIPv6, newIPv4, newIPv6 string) error {
	subject := fmt.Sprintf("⚠️ %s 获取异常警告", warningType)

	var detailMsg string
	if warningType == "IPv4" {
		detailMsg = fmt.Sprintf(`
			<p>之前的IPv4地址: <strong style="color: #dc3545;">%s</strong></p>
			<p>当前获取结果: <strong style="color: #ffc107;">获取失败</strong></p>
			<p>当前IPv6地址: <strong style="color: #28a745;">%s</strong> (正常)</p>
		`, oldIPv4, newIPv6)
	} else {
		detailMsg = fmt.Sprintf(`
			<p>之前的IPv6地址: <strong style="color: #dc3545;">%s</strong></p>
			<p>当前获取结果: <strong style="color: #ffc107;">获取失败</strong></p>
			<p>当前IPv4地址: <strong style="color: #28a745;">%s</strong> (正常)</p>
		`, oldIPv6, newIPv4)
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; background-color: #f5f7fa;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="background-color: #f5f7fa; padding: 30px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
                    <!-- 头部 -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #ffc107 0%%, #ff9800 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">
                                ⚠️ IP获取异常警告
                            </h1>
                            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 14px;">
                                %s 地址获取失败，但网络连接正常
                            </p>
                        </td>
                    </tr>
                    
                    <!-- 内容区域 -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <div style="background: #fff3cd; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
                                <h3 style="color: #856404; margin: 0 0 15px 0;">详细信息</h3>
                                %s
                            </div>
                            
                            <div style="background: #e7f5ff; border-radius: 12px; padding: 20px;">
                                <h3 style="color: #0c5460; margin: 0 0 15px 0;">建议操作</h3>
                                <ul style="color: #0c5460; margin: 0; padding-left: 20px;">
                                    <li>检查IP获取服务是否正常工作</li>
                                    <li>考虑添加更多备用IP获取服务</li>
                                    <li>检查是否有防火墙或代理阻止访问</li>
                                </ul>
                            </div>
                        </td>
                    </tr>
                    
                    <!-- 底部 -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #e9ecef;">
                            <p style="color: #6c757d; font-size: 13px; margin: 0;">
                                📧 此邮件由 <strong>IP地址监控系统</strong> 自动发送<br>
                                🕐 检测时间: %s
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, warningType, detailMsg, getCurrentTime())

	return sendEmail(subject, body)
}
