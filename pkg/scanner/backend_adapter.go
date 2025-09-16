package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

var severities = map[harbor.Severity]int{
	harbor.UNKNOWN:    0,
	harbor.NEGLIGIBLE: 1,
	harbor.LOW:        2,
	harbor.MEDIUM:     3,
	harbor.HIGH:       4,
	harbor.CRITICAL:   5,
}

func getRegistryFrom(req harbor.ScanRequest) string {
	return strings.ReplaceAll(strings.ReplaceAll(req.Registry.URL, "https://", ""), "http://", "")
}

func getUserAndPasswordFrom(authorization string) (string, string) {
	payload := strings.ReplaceAll(authorization, "Basic ", "")
	plain, _ := base64.StdEncoding.DecodeString(payload)
	splitted := strings.Split(string(plain), ":")

	return splitted[0], splitted[1]
}

func getImageFrom(req harbor.ScanRequest) string {
	result := fmt.Sprintf("%s/%s", getRegistryFrom(req), req.Artifact.Repository)
	if req.Artifact.Tag == "" {
		return result + fmt.Sprintf("@%s", req.Artifact.Digest)
	}
	return result + fmt.Sprintf(":%s", req.Artifact.Tag)
}
