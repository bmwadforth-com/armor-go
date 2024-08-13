package util_test

import (
	"github.com/bmwadforth-com/armor-go/src/util"
	"go.uber.org/zap/zapcore"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Perform any test setup here
	util.InitLogger(false, zapcore.DebugLevel)

	os.Exit(m.Run())

	// Perform any test teardown here
}
