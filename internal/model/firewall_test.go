package model

import "testing"

func TestDropsByDefault(t *testing.T) {
	tests := []struct {
		name    string
		actions []string
		want    bool
	}{
		{
			name:    "drop established only passes new flows",
			actions: []string{"aws:alert_strict", "aws:drop_established"},
		},
		{
			name:    "drop strict denies new flows",
			actions: []string{"aws:alert_strict", "aws:drop_established", "aws:drop_strict"},
			want:    true,
		},
		{
			name:    "alert only passes new flows",
			actions: []string{"aws:alert_strict", "aws:alert_established"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &FirewallPolicy{StatefulDefaultActions: tc.actions}
			if got := p.DropsByDefault(); got != tc.want {
				t.Fatalf("DropsByDefault() = %v, want %v", got, tc.want)
			}
		})
	}
}
