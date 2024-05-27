package scanner

import (
	"github.com/onsi/gomega/format"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestScanner(t *testing.T) {
	format.MaxLength = 9999
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}
