package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPServiceSendsCustomUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.UserAgent(); got != "IP-monitor/1.0" {
			t.Fatalf("User-Agent = %q，期望 %q", got, "IP-monitor/1.0")
		}
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	defer server.Close()

	result := TestIPService(server.URL, "ipv4")
	if !result.Success {
		t.Fatalf("IP 服务测试失败: %s", result.Error)
	}
	if result.IP != "203.0.113.1" {
		t.Fatalf("IP = %q，期望 %q", result.IP, "203.0.113.1")
	}
}
