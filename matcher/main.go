package main

import (
	"encoding/json"
	"errors"

	"github.com/google/osv-scalibr/semantic"
)

type event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type affectedRange struct {
	Type   string  `json:"type"`
	Events []event `json:"events"`
}

type request struct {
	Ecosystem string          `json:"ecosystem"`
	Version   string          `json:"version"`
	Ranges    []affectedRange `json:"ranges"`
	Versions  []string        `json:"versions"`
}

type response struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
}

func evaluate(input request) response {
	version, err := semantic.Parse(input.Version, input.Ecosystem)
	if err != nil {
		if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
			return response{Kind: "unsupported", Reason: err.Error()}
		}
		return response{Kind: "error", Reason: err.Error()}
	}
	for _, explicit := range input.Versions {
		comparison, compareErr := version.CompareStr(explicit)
		if compareErr != nil {
			return response{Kind: "error", Reason: compareErr.Error()}
		}
		if comparison == 0 {
			return response{Kind: "match"}
		}
	}
	unsupportedRange := false
	for _, affected := range input.Ranges {
		if affected.Type != "ECOSYSTEM" && affected.Type != "SEMVER" {
			unsupportedRange = true
			continue
		}
		isAffected := false
		for _, boundary := range affected.Events {
			if boundary.Introduced == "0" {
				isAffected = true
			} else if boundary.Introduced != "" {
				comparison, compareErr := version.CompareStr(boundary.Introduced)
				if compareErr != nil {
					return response{Kind: "error", Reason: compareErr.Error()}
				}
				if comparison >= 0 {
					isAffected = true
				}
			}
			for _, value := range []string{boundary.Fixed, boundary.Limit} {
				if value == "" {
					continue
				}
				comparison, compareErr := version.CompareStr(value)
				if compareErr != nil {
					return response{Kind: "error", Reason: compareErr.Error()}
				}
				if comparison >= 0 {
					isAffected = false
				}
			}
			if boundary.LastAffected != "" {
				comparison, compareErr := version.CompareStr(boundary.LastAffected)
				if compareErr != nil {
					return response{Kind: "error", Reason: compareErr.Error()}
				}
				if comparison > 0 {
					isAffected = false
				}
			}
		}
		if isAffected {
			return response{Kind: "match"}
		}
	}
	if unsupportedRange {
		return response{Kind: "unsupported", Reason: "unsupported range type"}
	}
	return response{Kind: "no_match"}
}

//nolint:unused // WebAssembly entrypoint referenced from main_js.go.
func compareJSON(raw string) string {
	var input request
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		encoded, _ := json.Marshal(response{Kind: "error", Reason: "invalid request JSON"})
		return string(encoded)
	}
	encoded, _ := json.Marshal(evaluate(input))
	return string(encoded)
}
