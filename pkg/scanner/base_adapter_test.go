package scanner

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("parseMainAssetName", func() {
	It("parses tagged repository without registry", func() {
		repo, tag, hash, ok := parseMainAssetName("sysdig/agent:9.7.0@sha256:abc")

		Expect(ok).To(BeTrue())
		Expect(repo).To(Equal("sysdig/agent"))
		Expect(tag).To(Equal("9.7.0"))
		Expect(hash).To(Equal("sha256:abc"))
	})

	It("parses digest-only repository without registry", func() {
		repo, tag, hash, ok := parseMainAssetName("sysdig/agent@sha256:abc")

		Expect(ok).To(BeTrue())
		Expect(repo).To(Equal("sysdig/agent"))
		Expect(tag).To(BeEmpty())
		Expect(hash).To(Equal("sha256:abc"))
	})

	It("parses tagged repository with registry and strips registry host", func() {
		repo, tag, hash, ok := parseMainAssetName("registry.example.com/sysdig/agent:latest@sha256:abc")

		Expect(ok).To(BeTrue())
		Expect(repo).To(Equal("sysdig/agent"))
		Expect(tag).To(Equal("latest"))
		Expect(hash).To(Equal("sha256:abc"))
	})

	It("parses digest-only repository with registry and strips registry host", func() {
		repo, tag, hash, ok := parseMainAssetName("registry.example.com/sysdig/agent@sha256:abc")

		Expect(ok).To(BeTrue())
		Expect(repo).To(Equal("sysdig/agent"))
		Expect(tag).To(BeEmpty())
		Expect(hash).To(Equal("sha256:abc"))
	})

	It("keeps repository untouched when first path segment is not a registry host", func() {
		repo, tag, hash, ok := parseMainAssetName("library/debian@sha256:abc")

		Expect(ok).To(BeTrue())
		Expect(repo).To(Equal("library/debian"))
		Expect(tag).To(BeEmpty())
		Expect(hash).To(Equal("sha256:abc"))
	})

	It("returns not ok for malformed values", func() {
		for _, tc := range []string{
			"",
			"@sha256:abc",
			"sysdig/agent@",
			"sysdig/agent",
			"sysdig/agent:1.0",
		} {
			repo, tag, hash, ok := parseMainAssetName(tc)
			Expect(ok).To(BeFalse(), fmt.Sprintf("mainAssetName=%q", tc))
			Expect(repo).To(BeEmpty())
			Expect(tag).To(BeEmpty())
			Expect(hash).To(BeEmpty())
		}
	})
})
