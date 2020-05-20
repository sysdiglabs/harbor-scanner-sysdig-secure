package scanner

import (
	"context"
	"crypto/md5"
	"fmt"

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
	if err := s.createJobFrom(req); err != nil {
		return harbor.ScanResponse{}, err
	}

	return harbor.ScanResponse{
		ID: createScanResponseID(req.Artifact.Repository, req.Artifact.Digest),
	}, nil
}

func (s *inlineAdapter) createJobFrom(req harbor.ScanRequest) error {
	job := s.buildJob(req)

	_, err := s.k8sClient.BatchV1().Jobs(s.namespace).Create(
		context.Background(),
		job,
		metav1.CreateOptions{})

	return err
}

func (s *inlineAdapter) buildJob(req harbor.ScanRequest) *batchv1.Job {
	name := fmt.Sprintf(
		"inline-scan-%x",
		md5.Sum([]byte(fmt.Sprintf("%s:%s", req.Artifact.Repository, req.Artifact.Digest))))

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: "OnFailure",
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
							Name:    "scanner",
							Image:   "sysdiglabs/secure-inline-scan",
							Command: []string{"/bin/bash"},
							Args: []string{
								"-c",
								fmt.Sprintf("docker login harbor.sysdig-demo.zone -u '$(HARBOR_ROBOTACCOUNT_USER)' -p '$(HARBOR_ROBOTACCOUNT_PASSWORD)' && (/bin/inline_scan.sh analyze -k '$(SYSDIG_SECURE_API_TOKEN)' -P %s || true )", getImageFrom(req)),
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
								{
									Name: "HARBOR_ROBOTACCOUNT_USER",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "harbor-scanner-sysdig-secure",
											},
											Key: "harbor_robot_account_name",
										},
									},
								},
								{
									Name: "HARBOR_ROBOTACCOUNT_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "harbor-scanner-sysdig-secure",
											},
											Key: "harbor_robot_account_password",
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "docker-daemon",
									MountPath: "/var/run/docker.sock",
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
										Name: "harbor-scanner-sysdig-secure",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "harbor_ca",
											Path: "ca.crt",
										},
									},
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
