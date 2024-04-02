package util_test

import (
	"github.com/bmwadforth/galaxy/src/util"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Perform any test setup here
	util.InitLogger()

	os.Exit(m.Run())

	// Perform any test teardown here
}