package logger

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestDebugLog_Enabled(t *testing.T) {
	// Save and restore original state
	originalEnabled := debugLogEnabled
	defer func() { debugLogEnabled = originalEnabled }()

	debugLogEnabled = true

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	DebugLog("test message %s", "value")

	output := buf.String()
	if !strings.Contains(output, "test message value") {
		t.Errorf("expected log output to contain 'test message value', got '%s'", output)
	}
}

func TestDebugLog_Disabled(t *testing.T) {
	originalEnabled := debugLogEnabled
	defer func() { debugLogEnabled = originalEnabled }()

	debugLogEnabled = false

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	DebugLog("this should not appear")

	output := buf.String()
	if output != "" {
		t.Errorf("expected no log output when debug disabled, got '%s'", output)
	}
}

func TestIsDebugLogEnabled_True(t *testing.T) {
	originalEnabled := debugLogEnabled
	defer func() { debugLogEnabled = originalEnabled }()

	debugLogEnabled = true
	if !IsDebugLogEnabled() {
		t.Error("expected IsDebugLogEnabled to return true")
	}
}

func TestIsDebugLogEnabled_False(t *testing.T) {
	originalEnabled := debugLogEnabled
	defer func() { debugLogEnabled = originalEnabled }()

	debugLogEnabled = false
	if IsDebugLogEnabled() {
		t.Error("expected IsDebugLogEnabled to return false")
	}
}

func TestDebugLog_FormatString(t *testing.T) {
	originalEnabled := debugLogEnabled
	defer func() { debugLogEnabled = originalEnabled }()

	debugLogEnabled = true

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	DebugLog("count: %d, name: %s", 42, "test")

	output := buf.String()
	if !strings.Contains(output, "count: 42, name: test") {
		t.Errorf("expected formatted log output, got '%s'", output)
	}
}
