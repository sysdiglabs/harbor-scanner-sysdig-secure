package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
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
	secureURL string
	namespace string
	secret    string
	verifySSL bool
	jobTTL    int32
}

func NewInlineAdapter(secureClient secure.Client, k8sClient kubernetes.Interface, secureURL string, namespace string, secret string, verifySSL bool) Adapter {
	return &inlineAdapter{
		BaseAdapter: BaseAdapter{secureClient: secureClient},
		k8sClient:   k8sClient,
		secureURL:   secureURL,
		namespace:   namespace,
		secret:      secret,
		verifySSL:   verifySSL,
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
	user, password := getUserAndPasswordFrom(req.Registry.Authorization)
	userPassword := fmt.Sprintf("%s:%s", user, password)

	var envVars = []corev1.EnvVar{
		{
			Name: "SYSDIG_API_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: i.secret,
					},
					Key: "sysdig_secure_api_token",
				},
			},
		},
	}

	// Propagate local proxy variables to the Job
	envVars = appendLocalEnvVar(envVars, "http_proxy")
	envVars = appendLocalEnvVar(envVars, "https_proxy")
	envVars = appendLocalEnvVar(envVars, "HTTPS_PROXY")
	envVars = appendLocalEnvVar(envVars, "no_proxy")
	envVars = appendLocalEnvVar(envVars, "NO_PROXY")

	cmdString := fmt.Sprintf("/sysdig-inline-scan.sh --sysdig-url %s -d %s --registry-skip-tls --registry-auth-basic '%s' ", i.secureURL, req.Artifact.Digest, userPassword)
	// Add --sysdig-skip-tls only if insecure
	if !i.verifySSL {
		cmdString += "--sysdig-skip-tls "
	}

	cmdString += getImageFrom(req)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &i.jobTTL,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: "OnFailure",
					Containers: []corev1.Container{
						{
							Name:    "scanner",
							Image:   "quay.io/sysdig/secure-inline-scan:2",
							Command: []string{"/bin/sh"},
							Args: []string{
								"-c",
								fmt.Sprintf("%s || true", cmdString),
							},
							Env: envVars,
						},
					},
				},
			},
		},
	}
}

func appendLocalEnvVar(envVars []corev1.EnvVar, key string) []corev1.EnvVar {
	if value, exists := os.LookupEnv(key); exists {
		envVars = append(envVars, corev1.EnvVar{
			Name:  key,
			Value: value,
		})
	}

	return envVars
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
