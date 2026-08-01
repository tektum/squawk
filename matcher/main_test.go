package main

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name string
		in   request
		want string
	}{
		{"Debian epoch", request{Ecosystem: "Debian", Version: "1:2.0-1", Ranges: []affectedRange{{Type: "ECOSYSTEM", Events: []event{{Introduced: "1:1.0-1"}, {Fixed: "1:3.0-1"}}}}}, "match"},
		{"Alpine revision outside", request{Ecosystem: "Alpine", Version: "1.2.3-r3", Ranges: []affectedRange{{Type: "ECOSYSTEM", Events: []event{{Introduced: "1.2.3-r0"}, {Fixed: "1.2.3-r2"}}}}}, "no_match"},
		{"semver boundary", request{Ecosystem: "npm", Version: "2.0.0", Ranges: []affectedRange{{Type: "SEMVER", Events: []event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, "no_match"},
		{"Maven range", request{Ecosystem: "Maven", Version: "1.5.0", Ranges: []affectedRange{{Type: "ECOSYSTEM", Events: []event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, "match"},
		{"PyPI range", request{Ecosystem: "PyPI", Version: "1.5.0", Ranges: []affectedRange{{Type: "ECOSYSTEM", Events: []event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, "match"},
		{"RubyGems range", request{Ecosystem: "RubyGems", Version: "1.5.0", Ranges: []affectedRange{{Type: "ECOSYSTEM", Events: []event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, "match"},
		{"NuGet range", request{Ecosystem: "NuGet", Version: "1.5.0", Ranges: []affectedRange{{Type: "ECOSYSTEM", Events: []event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, "match"},
		{"last affected inclusive", request{Ecosystem: "npm", Version: "1.5.0", Ranges: []affectedRange{{Type: "SEMVER", Events: []event{{Introduced: "1.0.0"}, {LastAffected: "1.5.0"}}}}}, "match"},
		{"limit exclusive", request{Ecosystem: "npm", Version: "2.0.0", Ranges: []affectedRange{{Type: "SEMVER", Events: []event{{Introduced: "1.0.0"}, {Limit: "2.0.0"}}}}}, "no_match"},
		{"Go pseudo version", request{Ecosystem: "Go", Version: "v0.0.0-20260101000000-abcdef123456", Versions: []string{"v0.0.0-20260101000000-abcdef123456"}}, "match"},
		{"unsupported", request{Ecosystem: "Unknown", Version: "1"}, "unsupported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evaluate(tt.in).Kind; got != tt.want {
				t.Fatalf("evaluate()=%q want %q", got, tt.want)
			}
		})
	}
}
