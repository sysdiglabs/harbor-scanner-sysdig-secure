package scanner_test

import (
	"context"
	"os"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure/mocks"
)

const (
	secureURL    = "https://secure.sysdig.com"
	namespace    = "a-namespace"
	secret       = "a-secret"
	resourceName = "inline-scan-1e668f7cc4c27e915cfed9793808357e"
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
			os.Setenv(key, item.value)
		} else {
			os.Unsetenv(key)
		}
	}
}

var _ = Describe("InlineAdapter", func() {
	var (
		controller    *gomock.Controller
		client        *mocks.MockClient
		inlineAdapter scanner.Adapter
		k8sClient     kubernetes.Interface
	)

	BeforeEach(func() {
		log.SetOutput(GinkgoWriter )
		controller = gomock.NewController(GinkgoT())
		client = mocks.NewMockClient(controller)
		k8sClient = fake.NewSimpleClientset()
		inlineAdapter = scanner.NewInlineAdapter(client, k8sClient, secureURL, namespace, secret, true, log.StandardLogger())
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("when scanning an image", func() {
		It("returns the scanID for checking if scan has finished", func() {
			result, _ := inlineAdapter.Scan(scanRequest())

			Expect(result).To(Equal(harbor.ScanResponse{ID: scanID}))
		})

		It("schedules the scanning job within namespace", func() {
			inlineAdapter.Scan(scanRequest())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result).To(Equal(job()))
		})

		It("proxy env vars are included in the Job environment", func() {

			savedEnv := saveEnv([]string{"http_proxy", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"})

			os.Setenv("http_proxy", "http_proxy-value")
			os.Setenv("https_proxy", "https_proxy-value")
			os.Setenv("HTTPS_PROXY", "HTTPS_PROXY-value")
			os.Setenv("no_proxy", "no_proxy-value")
			os.Setenv("NO_PROXY", "NO_PROXY-value")

			inlineAdapter.Scan(scanRequest())

			restoreEnv(savedEnv)

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "http_proxy", Value: "http_proxy-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "https_proxy", Value: "https_proxy-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "HTTPS_PROXY", Value: "HTTPS_PROXY-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "no_proxy", Value: "no_proxy-value"}))
			Expect(result.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "NO_PROXY", Value: "NO_PROXY-value"}))
		})

		It("adds --sysdig-skip-tls in insecure", func() {

			inlineAdapter = scanner.NewInlineAdapter(client, k8sClient, secureURL, namespace, secret, false, log.StandardLogger())

			inlineAdapter.Scan(scanRequest())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result.Spec.Template.Spec.Containers[0].Args).To(ContainElement(ContainSubstring("--sysdig-skip-tls")))
		})

		Context("when a job already exists", func() {
			It("returns the scanID for checking if scan has finished", func() {
				k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), activeJob(), metav1.CreateOptions{})

				result, err := inlineAdapter.Scan(scanRequest())

				Expect(result).To(Equal(harbor.ScanResponse{ID: scanID}))
				Expect(err).To(Succeed())
			})
		})
	})

	Context("when getting the vulnerability report for an image", func() {

		Context("when no job for image exists", func() {
			It("returns a ScanRequestID Not Found Error", func() {
				_, err := inlineAdapter.GetVulnerabilityReport(scanID)

				Expect(err).To(MatchError(scanner.ErrScanRequestIDNotFound))
			})
		})

		Context("when image is still being scanned", func() {
			It("returns a VulnerabilityReport is not Ready Error", func() {
				k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), activeJob(), metav1.CreateOptions{})

				_, err := inlineAdapter.GetVulnerabilityReport(scanID)

				Expect(err).To(MatchError(scanner.ErrVulnerabiltyReportNotReady))
			})
		})

		Context("when image scan is finished", func() {
			BeforeEach(func() {
				job := finishedJob()
				k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), job, metav1.CreateOptions{})
				pod := finishedPodForJob(job)
				k8sClient.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
			})

			It("queries Secure for the vulnerability list", func() {
				client.EXPECT().GetVulnerabilities(imageDigest).Return(secureVulnerabilityReport(), nil)
				client.EXPECT().GetImage(imageDigest).Return(scanResponse(), nil)
				client.EXPECT().GetVulnerabilityDescription("CVE-2019-9948", "CVE-2019-9946").Return(vulnerabilitiesDescription(), nil)

				result, _ := inlineAdapter.GetVulnerabilityReport(scanID)

				Expect(result).To(Equal(vulnerabilityReport()))
			})

			Context("when Secure returns an error", func() {
				It("returns the error", func() {
					client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, errSecure)

					_, err := inlineAdapter.GetVulnerabilityReport(scanID)

					Expect(err).To(MatchError(errSecure))
				})
			})
		})


	})
})

func job() *batchv1.Job {
	jobTTL := int32(3600)
	backoffLimit := int32(0)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &jobTTL,
			BackoffLimit: &backoffLimit,
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
								"/sysdig-inline-scan.sh --sysdig-url https://secure.sysdig.com -d an image digest --registry-skip-tls --registry-auth-basic 'robot$9f6711d1-834d-11ea-867f-76103d08dca8:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTAwMDk5OTksImlhdCI6MTU4NzQxNzk5OSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6OSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoic2Nhbm5lci1wdWxsIiwiRWZmZWN0IjoiIn1dfQ.A3_aTzvxqSTvl26pQKa97ay15zRPC9K55NE0WbEyOsY3m0KFz-HuSDatncWLSYvOlcGVdysKlF3JXYWIjQ7tEI4V76WA9UMoi-fr9vEEdWLF5C1uWZJOz_S72sQ3G1BzsLp3HyWe9ZN5EBK9mhXzYNv2rONYrr0UJeBmNnMf2mU3sH71OO_G6JvRl5fwFSLSYx8nQs82PhfVhx50wRuWl_zyeCCDy_ytLzjRBvZwKuI9iVIxgM1pRfKG15NWMHfl0lcYnjm7f1_WFGKtVddkLOTICK0_FPtef1L8A16ozo_2NA32WD9PstdcTuD37XbZ6AFXUAZFoZLfCEW97mtIZBY2uYMwDQtc6Nme4o3Ya-MnBEIAs9Vi9d5a4pkf7Two-xjI-9ESgVz79YqL-_OnecQPNJ9yAFtJuxQ7StfsCIZx84hh5VdcZmW9jlezRHh4hTAjsNmrOBFTAjPyaXk98Se3Fj0Ev3bChod63og4frE7_fE7HnoBKVPHRAdBhJ2yrAiPymfij_kD4ke1Vb0AxmGGOwRP2K3TZNqEdKcq89lU6lHYV2UfrWchuF3u4ieNEC1BGu1_m_c55f0YZH1FAq6evCyA0JnFuXzO4cCxC7WHzXXRGSC9Lm3LF7cbaZAgFj5d34gbgUQmJst8nPlpW-KtwRL-pHC6mipunCBv9bU' --format=JSON harbor.sysdig-demo.zone/sysdig/agent:9.7.0",
							},
							Env: []corev1.EnvVar{
								{
									Name: "SYSDIG_API_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: secret,
											},
											Key: "sysdig_secure_api_token",
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

func activeJob() *batchv1.Job {
	job := job()
	job.Status.Active = 1

	return job
}

func finishedJob() *batchv1.Job {
	job := job()
	job.Status.Active = 0

	return job
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
				corev1.ContainerStatus{
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
