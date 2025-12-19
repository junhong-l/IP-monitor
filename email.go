package main

import (
	"crypto/tls"
	"fmt"
	"log"
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
	from := config.SenderEmail
	password := config.SenderPassword
	smtpServer := config.SMTPServer
	smtpPort := config.SMTPPort
	to := config.Recipients

	// 构建邮件头
	header := make(map[string]string)
	header["From"] = from
	header["To"] = strings.Join(to, ",")
	header["Subject"] = "=?UTF-8?B?" + base64Encode(subject) + "?="
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for k, v := range header {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

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

// 使用TLS发送邮件（端口587，STARTTLS方式）
func sendMailTLS(addr, from, password, smtpServer string, to []string, message []byte) error {
	log.Printf("尝试TLS方式发送邮件到 %s", addr)
	
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

	log.Println("TLS邮件发送成功")
	client.Quit()
	return nil
}

// 使用SSL发送邮件（端口465）
func sendMailSSL(addr, from, password, smtpServer string, to []string, message []byte) error {
	log.Printf("尝试SSL方式发送邮件到 %s", addr)
	
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

	log.Println("SSL邮件发送成功")
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

// 格式化IP列表用于显示
func formatIPList(ips []string) string {
	if len(ips) == 0 {
		return "无"
	}
	return strings.Join(ips, "<br>")
}

// 获取当前时间字符串
func getCurrentTime() string {
	return fmt.Sprintf("%s", time.Now().Format("2006-01-02 15:04:05"))
}
