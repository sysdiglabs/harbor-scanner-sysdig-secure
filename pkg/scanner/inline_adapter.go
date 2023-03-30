package scanner

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

const jobDefaultTTL = 3600

var ErrInlineScanError = errors.New("error executing the inline scanner")

type inlineAdapter struct {
	BaseAdapter
	k8sClient   kubernetes.Interface
	secureURL   string
	namespace   string
	secret      string
	verifySSL   bool
	jobTTL      int32
	extraParams string
	logger      Logger
}

type podResults struct {
	LogBytes []byte
	ExitCode int
}

type Logger interface {
	Writer() *io.PipeWriter
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

func NewInlineAdapter(secureClient secure.Client, k8sClient kubernetes.Interface, secureURL, namespace, secret, extraParams string, verifySSL bool, logger Logger) Adapter {
	return &inlineAdapter{
		BaseAdapter: BaseAdapter{secureClient: secureClient},
		k8sClient:   k8sClient,
		secureURL:   secureURL,
		namespace:   namespace,
		secret:      secret,
		verifySSL:   verifySSL,
		jobTTL:      jobDefaultTTL,
		extraParams: extraParams,
		logger:      logger,
	}
}

func (i *inlineAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	err := i.createJobFrom(req)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	return i.CreateScanResponse(req.Artifact.Repository, req.Artifact.Digest), nil
}

func (i *inlineAdapter) createJobFrom(req harbor.ScanRequest) error {
	name := jobName(req.Artifact.Repository, req.Artifact.Digest)
	job := i.buildJob(name, req)

	i.logger.Infof("Creating job %s for %s", name, getImageFrom(req))
	_, err := i.k8sClient.BatchV1().Jobs(i.namespace).Create(
		context.Background(),
		job,
		metav1.CreateOptions{})

	if err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return err
		}

		i.logger.Infof("Job %s already exists", name)
	}

	return nil
}

func (i *inlineAdapter) buildJob(name string, req harbor.ScanRequest) *batchv1.Job {
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

	cmdString := fmt.Sprintf("/sysdig-inline-scan.sh --sysdig-url %s -d %s --registry-skip-tls --registry-auth-basic '%s' --format=JSON ", i.secureURL, req.Artifact.Digest, userPassword)

	// Add --sysdig-skip-tls only if insecure
	if !i.verifySSL {
		cmdString += "--sysdig-skip-tls "
	}

	if i.extraParams != "" {
		cmdString += fmt.Sprintf("%s ", i.extraParams)
	}

	cmdString += getImageFrom(req)
	cmdString += "; RC=$?; if [[ $RC -eq 1 ]]; then (exit 0); else (exit $RC); fi"
	var backoffLimit int32 = 0
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &i.jobTTL,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:    "scanner",
							Image:   "quay.io/sysdig/secure-inline-scan:2",
							Command: []string{"/bin/sh"},
							Args: []string{
								"-c",
								cmdString,
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

func (i *inlineAdapter) GetVulnerabilityReport(scanResponseID harbor.ScanRequestID) (harbor.VulnerabilityReport, error) {
	repository, shaDigest := i.DecodeScanResponseID(scanResponseID)

	name := jobName(repository, shaDigest)
	job, _ := i.k8sClient.BatchV1().Jobs(i.namespace).Get(context.Background(), name, metav1.GetOptions{})

	if job == nil {
		return harbor.VulnerabilityReport{}, ErrScanRequestIDNotFound
	}

	if job.Status.Active != 0 {
		i.logger.Infof("Scan for %s/%s still in progress in job %s", repository, shaDigest, name)
		return harbor.VulnerabilityReport{}, ErrVulnerabilityReportNotReady
	}

	defer i.cleanupJob(name)

	i.logger.Infof("Scan for %s/%s finished, collecting results from job %s", repository, shaDigest, name)
	podResults, err := i.collectPodResults(job)
	if err != nil {
		i.logger.Errorf("Error collecting inline scanner results for %s/%s:\n%s", repository, shaDigest, err)
		return harbor.VulnerabilityReport{}, ErrInlineScanError
	}

	if podResults.ExitCode != 0 && podResults.ExitCode != 1 {
		i.logger.Errorf("Error executing inline scanner for %s/%s:\n%s", repository, shaDigest, string(podResults.LogBytes))
		return harbor.VulnerabilityReport{}, ErrInlineScanError
	}

	vulnerabilityReport, err := i.secureClient.GetVulnerabilities(shaDigest)

	if err != nil {
		i.logger.Errorf("Error retrieving scan results from backend for %s/%s", repository, shaDigest)
		return harbor.VulnerabilityReport{}, err
	}

	return i.ToHarborVulnerabilityReport(repository, shaDigest, &vulnerabilityReport)
}

func (i *inlineAdapter) cleanupJob(name string) {
	propagationPolicy := metav1.DeletePropagationForeground
	err := i.k8sClient.BatchV1().Jobs(i.namespace).Delete(
		context.Background(),
		name,
		metav1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
		})

	if err != nil {
		i.logger.Errorf("Error deleting job %s: %s", name, err)
	}
}

func (i *inlineAdapter) collectPodResults(job *batchv1.Job) (*podResults, error) {

	pods, err := i.k8sClient.CoreV1().Pods(i.namespace).List(
		context.Background(),
		metav1.ListOptions{
			LabelSelector: fmt.Sprintf("controller-uid=%s", job.UID),
		})

	if err != nil {
		return nil, err
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("pod for job %s not found", job.Name)
	}

	pod := pods.Items[0]
	req := i.k8sClient.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
	podLogs, err := req.Stream(context.Background())
	if err != nil {
		return nil, err
	}

	defer podLogs.Close()

	logBytes, err := ioutil.ReadAll(podLogs)
	if err != nil {
		return nil, err
	}

	if pod.Status.ContainerStatuses[0].State.Terminated == nil {
		return nil, fmt.Errorf("pod for job %s is not terminated", job.Name)
	}

	return &podResults{
		LogBytes: logBytes,
		ExitCode: int(pod.Status.ContainerStatuses[0].State.Terminated.ExitCode),
	}, nil
}
