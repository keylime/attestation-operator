// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

// Package version exposes version information about the attestation operator. This includes a version
// number, of course, but potentially any other version specific information as required.
// All the information in here must be declared as variables and not as constants, as they are being set
// in release builds through the Golang linker.
package version

import (
	"runtime"
	"time"
)

// version of the attestation operator. This should be overwritten at compile time with a go linker flag.
var version string = "dev"

// gitCommit is the commit of the attestation operator at build time. This must be overwritten at compile time with a go linker flag.
var gitCommit string = "dev"

// gitTreeState is the state of the git tree at build time. This must be overwritten at compile time with a go linker flag.
// It will be "clean" if there are no local code changes, and "dirty" if the binary was built from locally modified code.
var gitTreeState string = "dev"

// buildDate is the date of when the build was triggered. This must be overwritten at compile time with a go linker flag.
// The buildDate should be set in RFC3339 format.
var buildDate string = "dev"

type Info struct {
	Version      string     `json:"version,omitempty"`
	GitCommit    string     `json:"git_commit,omitempty"`
	GitTreeState string     `json:"git_tree_state,omitempty"`
	BuildDate    *time.Time `json:"build_date,omitempty"`
	GoVersion    string     `json:"go_version,omitempty"`
	GoArch       string     `json:"go_arch,omitempty"`
	GoOS         string     `json:"go_os,omitempty"`
}

// Get returns all the details about the version information of the attestation operator.
func Get() *Info {
	var t *time.Time
	pt, err := time.Parse(time.RFC3339, buildDate)
	if err == nil {
		t = &pt
	}
	return &Info{
		Version:      version,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    t,
		GoVersion:    runtime.Version(),
		GoArch:       runtime.GOARCH,
		GoOS:         runtime.GOOS,
	}
}
