package main

import "testing"

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		name  string
		left  []string
		right []string
		want  bool
	}{
		{name: "相同", left: []string{"public_ipv4", "private_ipv4"}, right: []string{"public_ipv4", "private_ipv4"}, want: true},
		{name: "顺序不同", left: []string{"public_ipv4", "private_ipv4"}, right: []string{"private_ipv4", "public_ipv4"}, want: false},
		{name: "数量不同", left: []string{"public_ipv4"}, right: []string{"public_ipv4", "private_ipv4"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := equalStringSlices(tt.left, tt.right); got != tt.want {
				t.Fatalf("equalStringSlices() = %t，期望 %t", got, tt.want)
			}
		})
	}
}
