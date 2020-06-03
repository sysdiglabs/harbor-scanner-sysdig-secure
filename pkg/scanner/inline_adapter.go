package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

type inlineAdapter struct {
	BaseAdapter
	k8sClient kubernetes.Interface
	namespace string
	configMap string
	secret    string
	jobTTL    int32
}

func NewInlineAdapter(secureClient secure.Client, k8sClient kubernetes.Interface, namespace string, configMap string, secret string) Adapter {
	return &inlineAdapter{
		BaseAdapter: BaseAdapter{secureClient: secureClient},
		k8sClient:   k8sClient,
		namespace:   namespace,
		configMap:   configMap,
		secret:      secret,
		jobTTL:      int32(24 * time.Hour.Seconds()),
	}
}

func (i *inlineAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	if err := i.createJobFrom(req); err != nil {
		return harbor.ScanResponse{}, err
	}

	return i.CreateScanResponse(req.Artifact.Repository, req.Artifact.Digest), nil
}

func (i *inlineAdapter) createJobFrom(req harbor.ScanRequest) error {
	job := i.buildJob(req)

	_, err := i.k8sClient.BatchV1().Jobs(i.namespace).Create(
		context.Background(),
		job,
		metav1.CreateOptions{})

	if !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func (i *inlineAdapter) buildJob(req harbor.ScanRequest) *batchv1.Job {
	name := jobName(req.Artifact.Repository, req.Artifact.Digest)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &i.jobTTL,
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
								fmt.Sprintf("docker login harbor.sysdig-demo.zone -u '$(HARBOR_ROBOTACCOUNT_USER)' -p '$(HARBOR_ROBOTACCOUNT_PASSWORD)' && (/bin/inline_scan.sh analyze -k '$(SYSDIG_SECURE_API_TOKEN)' -d '%s' -P %s || true )", req.Artifact.Digest, getImageFrom(req)),
							},
							Env: []corev1.EnvVar{
								{
									Name: "SYSDIG_SECURE_API_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: i.secret,
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
												Name: i.secret,
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
												Name: i.secret,
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
										Name: i.configMap,
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

func jobName(repository string, shaDigest string) string {
	return fmt.Sprintf(
		"inline-scan-%x",
		md5.Sum([]byte(fmt.Sprintf("%s|%s", repository, shaDigest))))
}

func (i *inlineAdapter) GetVulnerabilityReport(scanResponseID string) (harbor.VulnerabilityReport, error) {
	repository, shaDigest := i.DecodeScanResponseID(scanResponseID)

	vulnerabilityReport, err := i.secureClient.GetVulnerabilities(shaDigest)
	if err != nil {
		if err == secure.ErrImageNotFound {
			job, _ := i.k8sClient.BatchV1().Jobs(i.namespace).Get(context.Background(), jobName(repository, shaDigest), metav1.GetOptions{})
			if job == nil {
				return harbor.VulnerabilityReport{}, ErrScanRequestIDNotFound
			}
			if job.Status.Active != 0 {
				return harbor.VulnerabilityReport{}, ErrVulnerabiltyReportNotReady
			}
		}
		return harbor.VulnerabilityReport{}, err
	}

	return i.ToHarborVulnerabilityReport(repository, shaDigest, &vulnerabilityReport)
}
