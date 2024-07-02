package scanner

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

const jobDefaultTTL = 86400

var ErrInlineScanError = errors.New("error executing the inline scanner")
var (
	severities = map[harbor.Severity]int{
		harbor.UNKNOWN:    0,
		harbor.NEGLIGIBLE: 1,
		harbor.LOW:        2,
		harbor.MEDIUM:     3,
		harbor.HIGH:       4,
		harbor.CRITICAL:   5,
	}
)

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
		BaseAdapter: BaseAdapter{secureClient: secureClient, logger: logger},
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

	i.logger.Infof("Creating job '%s' for %s", name, getImageFrom(req))
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
	i.logger.Infof("Building job for request - Registry: %+v", req.Registry)
	i.logger.Infof("Building job for request - Artifact: %+v", req.Artifact)
	user, password := getUserAndPasswordFrom(req.Registry.Authorization)

	var envVars = []corev1.EnvVar{
		{
			Name: "SECURE_API_TOKEN", //Renamed for CLI scanner
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

	//Pass in registry credential variables for CLI scanner to use the robot account that is created for us.
	envVars = append(envVars, corev1.EnvVar{
		Name:      "REGISTRY_USER",
		Value:     user,
		ValueFrom: nil,
	}, corev1.EnvVar{
		Name:      "REGISTRY_PASSWORD",
		Value:     password,
		ValueFrom: nil,
	})
	envVars = appendLocalEnvVar(envVars, "NO_PROXY")
	cmdString := fmt.Sprintf("/home/nonroot/sysdig-cli-scanner -a %s --skiptlsverify --console-log --loglevel info ", i.secureURL)
	// Add skiptlsverify if insecure
	if !i.verifySSL {
		cmdString += "--skiptlsverify "
	}

	if i.extraParams != "" {
		cmdString += fmt.Sprintf("%s ", i.extraParams)
	}

	cmdString += fmt.Sprintf("pull://%s", getImageFrom(req))
	cmdString += "; RC=$?; if [ $RC -eq 1 ]; then exit 0; else exit $RC; fi"

	//Create security contexts for pod from main deployment
	// Retrieve the security context from the first container
	deploymentName := "harbor-scanner-sysdig-secure"
	cliScannerNamespace := os.Getenv("NAMESPACE_NAME") //Comes from the helm chart .Release.Namespace value
	var containerSecurityContext *corev1.SecurityContext
	var podSecurityContext *corev1.PodSecurityContext

	k8sDeployment, err := i.k8sClient.AppsV1().Deployments(cliScannerNamespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			i.logger.Infof("Deployment %s in namespace %s not found\n", deploymentName, cliScannerNamespace)
		} else {
			i.logger.Infof("Deployment %s in namespace %s Retrieval Error: %v", deploymentName, cliScannerNamespace, err)
		}
	} else {
		podSecurityContext = k8sDeployment.Spec.Template.Spec.SecurityContext
		podTemplate := k8sDeployment.Spec.Template
		if len(podTemplate.Spec.Containers) > 0 && podTemplate.Spec.Containers[0].SecurityContext != nil {
			containerSecurityContext = podTemplate.Spec.Containers[0].SecurityContext
			i.logger.Infof("Security context for container %s: %+v\n", podTemplate.Spec.Containers[0].Name, containerSecurityContext)
		} else {
			i.logger.Infof("No security context found for the container")
		}
	}
	i.logger.Infof("Building job with pod security context: %+v", podSecurityContext)
	i.logger.Infof("Building job with container security context: %+v", containerSecurityContext)

	var commandFinal = []string{"/busybox/sh"}
	var commandArgs = []string{"-c", cmdString}
	i.logger.Infof("Building job with Command Line: '%s'", commandFinal)
	i.logger.Infof("Building job with Args: '%s'", commandArgs)
	var backoffLimit int32 = 0
	var cliScannerJob = &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &i.jobTTL,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy:   corev1.RestartPolicyNever,
					SecurityContext: podSecurityContext,
					Containers: []corev1.Container{
						{
							Name:            "scanner",
							Image:           os.Getenv("CLI_SCANNER_IMAGE"), // Using my image but for production we would host it
							Command:         commandFinal,
							Args:            commandArgs,
							Env:             envVars,
							SecurityContext: containerSecurityContext,
						},
					},
				},
			},
		},
	}
	i.logger.Infof("Complete Job Definitions: '%+v'", cliScannerJob)
	return cliScannerJob
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
		"cli-scanner-%x", md5.Sum([]byte(fmt.Sprintf("%s|%s", repository, shaDigest))))
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
		i.logger.Errorf("Error collecting inline scanner results for %s/%s:%s", repository, shaDigest, err)
		return harbor.VulnerabilityReport{}, ErrInlineScanError
	}

	if podResults.ExitCode != 0 && podResults.ExitCode != 1 {
		i.logger.Errorf("Error executing inline scanner for %s/%s:%s", repository, shaDigest, string(podResults.LogBytes))
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

	defer func(podLogs io.ReadCloser) {
		if err := podLogs.Close(); err != nil {
			return
		}
	}(podLogs)

	logBytes, err := io.ReadAll(podLogs)
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
	return result + fmt.Sprintf(":%s@%s", req.Artifact.Tag, req.Artifact.Digest)
}
