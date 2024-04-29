package authn

import (
	"reflect"
	"testing"
)

func Test_cleanActions(t *testing.T) {
	tests := []struct {
		name    string
		actions []string
		want    []string
	}{
		{
			name: "nil action",
		},
		{
			name:    "empty action",
			actions: []string{},
		},
		{
			name: "single action",
			actions: []string{
				"pull",
			},
			want: []string{
				"pull",
			},
		},
		{
			name: "single empty action",
			actions: []string{
				"",
			},
		},
		{
			name: "multiple actions",
			actions: []string{
				"pull",
				"push",
			},
			want: []string{
				"pull",
				"push",
			},
		},
		{
			name: "multiple actions with empty action",
			actions: []string{
				"pull",
				"",
				"push",
			},
			want: []string{
				"pull",
				"push",
			},
		},
		{
			name: "multiple actions with all empty action",
			actions: []string{
				"",
				"",
				"",
			},
			want: nil,
		},
		{
			name: "unordered actions",
			actions: []string{
				"push",
				"pull",
				"delete",
			},
			want: []string{
				"delete",
				"pull",
				"push",
			},
		},
		{
			name: "wildcard",
			actions: []string{
				"*",
			},
			want: []string{
				"*",
			},
		},
		{
			name: "wildcard at the beginning",
			actions: []string{
				"*",
				"push",
				"pull",
				"delete",
			},
			want: []string{
				"*",
			},
		},
		{
			name: "wildcard in the middle",
			actions: []string{
				"push",
				"pull",
				"*",
				"delete",
			},
			want: []string{
				"*",
			},
		},
		{
			name: "wildcard at the end",
			actions: []string{
				"push",
				"pull",
				"delete",
				"*",
			},
			want: []string{
				"*",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanActions(tt.actions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cleanActions() = %v, want %v", got, tt.want)
			}
		})
	}
}
