package scanner

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestScanner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}
