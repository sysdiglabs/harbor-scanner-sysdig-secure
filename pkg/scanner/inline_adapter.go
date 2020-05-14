package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

type inlineAdapter struct {
	secureClient secure.Client
	k8sClient    kubernetes.Interface
	namespace    string
}

func NewInlineAdapter(secureClient secure.Client, k8sClient kubernetes.Interface, namespace string) Adapter {
	return &inlineAdapter{
		secureClient: secureClient,
		k8sClient:    k8sClient,
		namespace:    namespace,
	}
}

func (s *inlineAdapter) GetMetadata() harbor.ScannerAdapterMetadata {
	return scannerAdapterMetadata
}

func (s *inlineAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	s.createNamespace()
	s.createSecretFrom(req)

	return harbor.ScanResponse{
		ID: createScanResponseID(req.Artifact.Repository, req.Artifact.Digest),
	}, nil
}

func (s *inlineAdapter) createNamespace() error {
	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.namespace,
		},
	}

	_, err := s.k8sClient.CoreV1().Namespaces().Create(context.Background(), &namespace, metav1.CreateOptions{})

	return err
}

func (s *inlineAdapter) createSecretFrom(req harbor.ScanRequest) error {
	secret := buildSecret(req)

	_, err := s.k8sClient.CoreV1().Secrets(s.namespace).Create(
		context.Background(),
		&secret,
		metav1.CreateOptions{})

	return err
}

func buildSecret(req harbor.ScanRequest) v1.Secret {
	name := fmt.Sprintf(
		"inline-scan-demo-%s",
		createScanResponseID(req.Artifact.Repository, req.Artifact.Digest),
	)

	return v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: map[string][]byte{
			"config.json": dockerCredentialsFrom(req),
		},
	}
}

func dockerCredentialsFrom(req harbor.ScanRequest) []byte {
	registry := getRegistryFrom(req)
	credentials := strings.ReplaceAll(req.Registry.Authorization, "Basic ", "")

	return []byte(fmt.Sprintf(`{"auths": {"%s": { "auth": "%s" }}}`, registry, credentials))
}

func (s *inlineAdapter) GetVulnerabilityReport(scanResponseID string) (harbor.VulnerabilityReport, error) {
	return harbor.VulnerabilityReport{}, errors.New("Not implemented")
}
