package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expectExit   bool
		expectCode   int
		expectStdout string
		expectStderr string
	}{
		{name: "no arguments", args: nil, expectExit: false, expectCode: 0},
		{name: "help", args: []string{"--help"}, expectExit: true, expectCode: 0, expectStderr: "Usage: tsiam"},
		{name: "short help", args: []string{"-h"}, expectExit: true, expectCode: 0, expectStderr: "Usage: tsiam"},
		{name: "version", args: []string{"--version"}, expectExit: true, expectCode: 0, expectStdout: "tsiam "},
		{name: "unknown flag", args: []string{"--foo"}, expectExit: true, expectCode: 2, expectStderr: "flag provided but not defined: -foo"},
		{name: "unexpected argument", args: []string{"/bin/tsiam"}, expectExit: true, expectCode: 2, expectStderr: "Unexpected argument: /bin/tsiam"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exit, code := handleArgs(tt.args, &stdout, &stderr)
			assert.Equal(t, tt.expectExit, exit)
			assert.Equal(t, tt.expectCode, code)
			if tt.expectStdout == "" {
				assert.Empty(t, stdout.String())
			} else {
				assert.Contains(t, stdout.String(), tt.expectStdout)
			}
			if tt.expectStderr == "" {
				assert.Empty(t, stderr.String())
			} else {
				assert.Contains(t, stderr.String(), tt.expectStderr)
			}
		})
	}
}
