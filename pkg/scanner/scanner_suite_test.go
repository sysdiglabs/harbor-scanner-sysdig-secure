package scanner

import (
	"testing"

	"github.com/onsi/gomega/format"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestScanner(t *testing.T) {
	format.MaxLength = 9999
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}
