package authn_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

func TestRepositoryScope(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		actions    []string
		want       string
	}{
		{
			name: "empty repository",
			actions: []string{
				"pull",
			},
		},
		{
			name:       "nil actions",
			repository: "foo",
		},
		{
			name:       "empty actions",
			repository: "foo",
			actions:    []string{},
		},
		{
			name:       "empty actions list",
			repository: "foo",
			actions:    []string{},
		},
		{
			name:       "empty actions",
			repository: "foo",
			actions: []string{
				"",
			},
		},
		{
			name:       "single action",
			repository: "foo",
			actions: []string{
				"pull",
			},
			want: "repository:foo:pull",
		},
		{
			name:       "multiple actions",
			repository: "foo",
			actions: []string{
				"pull",
				"push",
			},
			want: "repository:foo:pull,push",
		},
		{
			name:       "unordered actions",
			repository: "foo",
			actions: []string{
				"push",
				"pull",
			},
			want: "repository:foo:pull,push",
		},
		{
			name:       "duplicated actions",
			repository: "foo",
			actions: []string{
				"push",
				"pull",
				"pull",
				"delete",
				"push",
			},
			want: "repository:foo:delete,pull,push",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authn.RepositoryScope(tt.repository, tt.actions...); got != tt.want {
				t.Errorf("ScopeRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithScopes(t *testing.T) {
	ctx := context.Background()

	// with single scope
	want := []string{
		"repository:foo:pull",
	}
	ctx = authn.WithScopes(ctx, want...)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(WithScopes()) = %v, want %v", got, want)
	}

	// overwrite scopes
	want = []string{
		"repository:bar:push",
	}
	ctx = authn.WithScopes(ctx, want...)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(WithScopes()) = %v, want %v", got, want)
	}

	// overwrite scopes with de-duplication
	scopes := []string{
		"repository:hello-world:push",
		"repository:alpine:delete",
		"repository:hello-world:pull",
		"repository:alpine:delete",
	}
	want = []string{
		"repository:alpine:delete",
		"repository:hello-world:pull,push",
	}
	ctx = authn.WithScopes(ctx, scopes...)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(WithScopes()) = %v, want %v", got, want)
	}

	// clean scopes
	want = nil
	ctx = authn.WithScopes(ctx, want...)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(WithScopes()) = %v, want %v", got, want)
	}
}

func TestAppendScopes(t *testing.T) {
	ctx := context.Background()

	// append single scope
	want := []string{
		"repository:foo:pull",
	}
	ctx = authn.AppendScopes(ctx, want...)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(AppendScopes()) = %v, want %v", got, want)
	}

	// append scopes with de-duplication
	scopes := []string{
		"repository:hello-world:push",
		"repository:alpine:delete",
		"repository:hello-world:pull",
		"repository:alpine:delete",
	}
	want = []string{
		"repository:alpine:delete",
		"repository:foo:pull",
		"repository:hello-world:pull,push",
	}
	ctx = authn.AppendScopes(ctx, scopes...)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(AppendScopes()) = %v, want %v", got, want)
	}

	// append empty scopes
	ctx = authn.AppendScopes(ctx)
	if got := authn.GetScopes(ctx); !reflect.DeepEqual(got, want) {
		t.Errorf("GetScopes(AppendScopes()) = %v, want %v", got, want)
	}
}

func TestCleanScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{
			name: "nil scope",
		},
		{
			name:   "empty scope",
			scopes: []string{},
		},
		{
			name: "single scope",
			scopes: []string{
				"repository:foo:pull",
			},
			want: []string{
				"repository:foo:pull",
			},
		},
		{
			name: "single scope with unordered actions",
			scopes: []string{
				"repository:foo:push,pull,delete",
			},
			want: []string{
				"repository:foo:delete,pull,push",
			},
		},
		{
			name: "single scope with duplicated actions",
			scopes: []string{
				"repository:foo:push,pull,push,pull,push,push,pull",
			},
			want: []string{
				"repository:foo:pull,push",
			},
		},
		{
			name: "single scope with wild cards",
			scopes: []string{
				"repository:foo:pull,*,push",
			},
			want: []string{
				"repository:foo:*",
			},
		},
		{
			name: "single scope with no actions",
			scopes: []string{
				"repository:foo:,",
			},
			want: nil,
		},
		{
			name: "multiple scopes",
			scopes: []string{
				"repository:bar:push",
				"repository:foo:pull",
			},
			want: []string{
				"repository:bar:push",
				"repository:foo:pull",
			},
		},
		{
			name: "multiple unordered scopes",
			scopes: []string{
				"repository:foo:pull",
				"repository:bar:push",
			},
			want: []string{
				"repository:bar:push",
				"repository:foo:pull",
			},
		},
		{
			name: "multiple scopes with duplicates",
			scopes: []string{
				"repository:foo:pull",
				"repository:bar:push",
				"repository:foo:push",
				"repository:bar:push,delete,pull",
				"repository:bar:delete,pull",
				"repository:foo:pull",
				"registry:catalog:*",
				"registry:catalog:pull",
			},
			want: []string{
				"registry:catalog:*",
				"repository:bar:delete,pull,push",
				"repository:foo:pull,push",
			},
		},
		{
			name: "multiple scopes with no actions",
			scopes: []string{
				"repository:foo:,",
				"repository:bar:,",
			},
			want: nil,
		},
		{
			name: "single unknown or invalid scope",
			scopes: []string{
				"unknown",
			},
			want: []string{
				"unknown",
			},
		},
		{
			name: "multiple unknown or invalid scopes",
			scopes: []string{
				"repository:foo:pull",
				"unknown",
				"invalid:scope",
				"no:actions:",
				"repository:foo:push",
			},
			want: []string{
				"invalid:scope",
				"repository:foo:pull,push",
				"unknown",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authn.CleanScopes(tt.scopes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CleanScopes() = %v, want %v", got, tt.want)
			}
		})
	}
}
