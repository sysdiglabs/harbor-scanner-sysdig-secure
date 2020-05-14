package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
	s.createSecretFrom(req)
	s.createJobFrom(req)

	return harbor.ScanResponse{
		ID: createScanResponseID(req.Artifact.Repository, req.Artifact.Digest),
	}, nil
}

func (s *inlineAdapter) createNamespace() error {
	namespace := corev1.Namespace{
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

func buildSecret(req harbor.ScanRequest) corev1.Secret {
	name := fmt.Sprintf(
		"inline-scan-demo-%s",
		createScanResponseID(req.Artifact.Repository, req.Artifact.Digest),
	)

	return corev1.Secret{
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

func (s *inlineAdapter) createJobFrom(req harbor.ScanRequest) error {
	job := buildJob(req)

	_, err := s.k8sClient.BatchV1().Jobs(s.namespace).Create(
		context.Background(),
		job,
		metav1.CreateOptions{})

	return err
}

func buildJob(req harbor.ScanRequest) *batchv1.Job {
	name := fmt.Sprintf(
		"inline-scan-demo-%s",
		createScanResponseID(req.Artifact.Repository, req.Artifact.Digest),
	)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "harbor-certificate-dumper",
							Image: "busybox",
							Command: []string{
								"sh",
								"-c",
								"mkdir -p /etc/docker/certs.d/harbor.sysdig-demo.zone && cp /tmp/ca.crt /etc/docker/certs.d/harbor.sysdig-demo.zone",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "docker-certificates",
									MountPath: "/etc/docker/certs.d",
									ReadOnly:  false,
								},
								{
									Name:      "certificate",
									MountPath: "/tmp",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "scanner",
							Image: "sysdiglabs/secure-inline-scan",
							Args: []string{
								"analyze",
								"-k",
								"$SYSDIG_SECURE_API_TOKEN",
								"-P",
								fmt.Sprintf("%s:%s", req.Artifact.Repository, req.Artifact.Tag),
							},
							Env: []corev1.EnvVar{
								{
									Name: "SYSDIG_SECURE_API_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "harbor-scanner-sysdig-secure",
											},
											Key: "sysdig_secure_api_token",
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "docker-daemon",
									MountPath: "/var/run/docker.sock",
								},
								{
									Name:      "docker-login",
									MountPath: "/root/.docker",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "docker-daemon",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
						{
							Name: "docker-certificates",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/docker/certs.d",
								},
							},
						},
						{
							Name: "certificate",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "harbor-certificate",
									},
								},
							},
						},
						{
							Name: "docker-login",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: name,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (s *inlineAdapter) GetVulnerabilityReport(scanResponseID string) (harbor.VulnerabilityReport, error) {
	return harbor.VulnerabilityReport{}, errors.New("Not implemented")
}
