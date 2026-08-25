package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildEmailMessageKeepsSMTPLineLengthsWithinLimit(t *testing.T) {
	recipients := make([]string, 40)
	for i := range recipients {
		recipients[i] = "long-recipient-address-" + string(rune('a'+i%26)) + "@example.example.com"
	}

	body := strings.Repeat("<div style=\"font-family: monospace;\">2001:db8::1</div>", 100)
	message := buildEmailMessage("sender@example.com", recipients, "测试邮件", body)

	for _, line := range strings.Split(message, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("SMTP 行长度为 %d，超过 998 字节限制", len(line))
		}
	}
}

func TestEncodeBase64BodyRoundTrips(t *testing.T) {
	body := "<p>测试邮件正文：2001:db8::1</p>"
	encoded := strings.ReplaceAll(encodeBase64Body(body), "\r\n", "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("正文不是有效的 Base64：%v", err)
	}
	if string(decoded) != body {
		t.Fatalf("解码正文不一致：得到 %q，期望 %q", decoded, body)
	}
}
