package secure_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSecure(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sysdig Secure Suite")
}
