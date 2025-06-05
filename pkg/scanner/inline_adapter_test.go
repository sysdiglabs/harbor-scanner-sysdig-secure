package scanner

import (
	"context"
	"os"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure/mocks"
)

const (
	secureURL    = "https://secure.sysdig.com"
	namespace    = "a-namespace"
	secret       = "a-secret"
	resourceName = "cli-scanner-1e668f7cc4c27e915cfed9793808357e"
)

type envItem struct {
	value   string
	defined bool
}

func saveEnv(keys []string) map[string]envItem {
	envItems := make(map[string]envItem)
	for _, key := range keys {
		value, defined := os.LookupEnv(key)
		envItems[key] = envItem{
			value:   value,
			defined: defined,
		}
	}

	return envItems
}

func restoreEnv(savedItems map[string]envItem) {
	for key, item := range savedItems {
		if item.defined {
			Expect(os.Setenv(key, item.value)).To(Succeed())
		} else {
			Expect(os.Unsetenv(key)).To(Succeed())
		}
	}
}

var _ = Describe("InlineAdapter", func() {
	var (
		controller *gomock.Controller
		client     *mocks.MockClient
		adapter    Adapter
		k8sClient  kubernetes.Interface
	)

	BeforeEach(func() {
		log.SetOutput(GinkgoWriter)
		controller = gomock.NewController(GinkgoT())
		client = mocks.NewMockClient(controller)
		k8sClient = fake.NewSimpleClientset()
		adapter = NewInlineAdapter(client, k8sClient, secureURL, namespace, secret, "", true, log.StandardLogger())
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("when scanning an image", func() {
		It("returns the scanID for checking if scan has finished", func() {
			result, _ := adapter.Scan(scanRequest())

			Expect(result).To(Equal(harbor.ScanResponse{ID: scanID}))
		})

		It("schedules the scanning job within namespace", func() {
			Expect(adapter.Scan(scanRequest())).To(Succeed())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result).To(Equal(job()))
		})

		It("proxy env vars are included in the Job environment", func() {
			savedEnv := saveEnv([]string{"http_proxy", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"})

			Expect(os.Setenv("http_proxy", "http_proxy-value")).To(Succeed())
			Expect(os.Setenv("https_proxy", "https_proxy-value")).To(Succeed())
			Expect(os.Setenv("HTTPS_PROXY", "HTTPS_PROXY-value")).To(Succeed())
			Expect(os.Setenv("no_proxy", "no_proxy-value")).To(Succeed())
			Expect(os.Setenv("NO_PROXY", "NO_PROXY-value")).To(Succeed())

			Expect(adapter.Scan(scanRequest())).To(Succeed())

			restoreEnv(savedEnv)

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "http_proxy", Value: "http_proxy-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "https_proxy", Value: "https_proxy-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "HTTPS_PROXY", Value: "HTTPS_PROXY-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "no_proxy", Value: "no_proxy-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "NO_PROXY", Value: "NO_PROXY-value"}))
		})

		It("adds --skiptlsverify in insecure", func() {
			adapter = NewInlineAdapter(client, k8sClient, secureURL, namespace, secret, "", false, log.StandardLogger())

			Expect(adapter.Scan(scanRequest())).To(Succeed())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result.Spec.Template.Spec.Containers[0].Args).To(ContainElement(ContainSubstring("--skiptlsverify")))
		})

		It("adds extra parameters", func() {
			adapter = NewInlineAdapter(client, k8sClient, secureURL, namespace, secret, "--foo --bar", false, log.StandardLogger())

			Expect(adapter.Scan(scanRequest())).To(Succeed())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result.Spec.Template.Spec.Containers[0].Args).To(ContainElement(ContainSubstring(" --foo --bar ")))
		})

		Context("when a job already exists", func() {
			It("returns the scanID for checking if scan has finished", func() {
				Expect(k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), activeJob(), metav1.CreateOptions{})).To(Succeed())

				result, err := adapter.Scan(scanRequest())

				Expect(result).To(Equal(harbor.ScanResponse{ID: scanID}))
				Expect(err).To(Succeed())
			})
		})
	})

	Context("when getting the vulnerability report for an image", func() {
		Context("when no job for image exists", func() {
			It("returns a ScanRequestID Not Found Error", func() {
				_, err := adapter.GetVulnerabilityReport(scanID)

				Expect(err).To(MatchError(ErrScanRequestIDNotFound))
			})
		})

		Context("when image is still being scanned", func() {
			It("returns a VulnerabilityReport is not Ready Error", func() {
				Expect(k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), activeJob(), metav1.CreateOptions{})).To(Succeed())

				_, err := adapter.GetVulnerabilityReport(scanID)

				Expect(err).To(MatchError(ErrVulnerabilityReportNotReady))
			})
		})

		Context("when image scan is finished", func() {
			BeforeEach(func() {
				job := finishedJob()
				Expect(k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), job, metav1.CreateOptions{})).To(Succeed())
				pod := finishedPodForJob(job)
				Expect(k8sClient.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})).To(Succeed())
			})

			It("queries Secure for the vulnerability list", func() {
				client.EXPECT().GetVulnerabilities(imageDigest).Return(secureVulnerabilityReport(), nil)
				client.EXPECT().GetImage(imageDigest).Return(scanResponse(), nil)
				// client.EXPECT().GetVulnerabilityDescription("CVE-2019-9948", "CVE-2019-9946").Return(vulnerabilitiesDescription(), nil)

				result, _ := adapter.GetVulnerabilityReport(scanID)

				Expect(result).To(Equal(vulnerabilityReport()))
			})

			Context("when Secure returns an error", func() {
				It("returns the error", func() {
					client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, errSecure)

					_, err := adapter.GetVulnerabilityReport(scanID)

					Expect(err).To(MatchError(errSecure))
				})
			})
		})
	})
})

func job() *batchv1.Job {
	jobTTL := int32(86400)
	backoffLimit := int32(0)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &jobTTL,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:    "scanner",
							Image:   os.Getenv("CLI_SCANNER_IMAGE"),
							Command: []string{"/busybox/sh"},
							Args: []string{
								"-c",
								"/home/nonroot/sysdig-cli-scanner -a https://secure.sysdig.com --skiptlsverify --output-json=output.json pull://harbor.sysdig-demo.zone/sysdig/agent:9.7.0@an image digest; RC=$?; if [ $RC -eq 1 ]; then exit 0; else exit $RC; fi",
							},
							Env: []corev1.EnvVar{
								{
									Name: "SECURE_API_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: secret,
											},
											Key: "sysdig_secure_api_token",
										},
									},
								},
								{
									Name:      "REGISTRY_USER",
									Value:     user,
									ValueFrom: nil,
								},
								{
									Name:      "REGISTRY_PASSWORD",
									Value:     password,
									ValueFrom: nil,
								},
							},
						},
					},
				},
			},
		},
	}
}

func activeJob() *batchv1.Job {
	j := job()
	j.Status.Active = 1

	return j
}

func finishedJob() *batchv1.Job {
	j := job()
	j.Status.Active = 0

	return j
}

func finishedPodForJob(j *batchv1.Job) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: namespace,
			Labels: map[string]string{
				"controller-uid": string(j.UID),
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 0,
						},
					},
				},
			},
		},
	}
}
