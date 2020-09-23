package scanner_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

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

var _ = Describe("InlineAdapter", func() {
	var (
		controller    *gomock.Controller
		client        *mocks.MockClient
		inlineAdapter scanner.Adapter
		k8sClient     kubernetes.Interface
	)

	BeforeEach(func() {
		controller = gomock.NewController(GinkgoT())
		client = mocks.NewMockClient(controller)
		k8sClient = fake.NewSimpleClientset()
		inlineAdapter = scanner.NewInlineAdapter(client, k8sClient, secureURL, namespace, secret)
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
		It("queries Secure for the vulnerability list", func() {
			client.EXPECT().GetVulnerabilities(imageDigest).Return(secureVulnerabilityReport(), nil)
			client.EXPECT().GetImage(imageDigest).Return(scanResponse(), nil)
			client.EXPECT().GetVulnerabilityDescription("CVE-2019-9948", "CVE-2019-9946").Return(vulnerabilitiesDescription(), nil)

			result, _ := inlineAdapter.GetVulnerabilityReport(scanID)

			Expect(result).To(Equal(vulnerabilityReport()))
		})

		Context("when Secure returns an error", func() {
			Context("when Secure cannot find the image scanned and no job for image exists", func() {
				It("returns a ScanRequestID Not Found Error", func() {
					client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, secure.ErrImageNotFound)

					_, err := inlineAdapter.GetVulnerabilityReport(scanID)

					Expect(err).To(MatchError(scanner.ErrScanRequestIDNotFound))
				})
			})

			Context("when image is still being scanned", func() {
				It("returns a VulnerabilityReport is not Ready Error", func() {
					client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, secure.ErrImageNotFound)
					k8sClient.BatchV1().Jobs(namespace).Create(context.Background(), activeJob(), metav1.CreateOptions{})

					_, err := inlineAdapter.GetVulnerabilityReport(scanID)

					Expect(err).To(MatchError(scanner.ErrVulnerabiltyReportNotReady))
				})
			})

			It("returns the error", func() {
				client.EXPECT().GetVulnerabilities(imageDigest).Return(secure.VulnerabilityReport{}, errSecure)

				_, err := inlineAdapter.GetVulnerabilityReport(scanID)

				Expect(err).To(MatchError(errSecure))
			})
		})
	})
})

func getUserAndPasswordFromSecret(k8sClient kubernetes.Interface, namespace string, name string) (string, string) {
	secret, _ := k8sClient.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})

	var parsed map[string]interface{}
	json.Unmarshal(secret.Data["config.json"], &parsed)

	encodedCredentials := parsed["auths"].(map[string]interface{})["harbor.sysdig-demo.zone"].(map[string]interface{})["auth"].(string)
	basicAuthCredentials, _ := base64.StdEncoding.DecodeString(encodedCredentials)
	credentials := strings.Split(string(basicAuthCredentials), ":")

	return credentials[0], credentials[1]
}

func job() *batchv1.Job {
	jobTTL := int32(86400)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &jobTTL,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: "OnFailure",
					Containers: []corev1.Container{
						{
							Name:    "scanner",
							Image:   "sysdiglabs/sysdig-inline-scan:harbor-1.0",
							Command: []string{"/bin/sh"},
							Args: []string{
								"-c",
								"/sysdig-inline-scan.sh -s https://secure.sysdig.com -k '$(SYSDIG_SECURE_API_TOKEN)' -d an image digest -P -n -u robot$9f6711d1-834d-11ea-867f-76103d08dca8:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTAwMDk5OTksImlhdCI6MTU4NzQxNzk5OSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6OSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoic2Nhbm5lci1wdWxsIiwiRWZmZWN0IjoiIn1dfQ.A3_aTzvxqSTvl26pQKa97ay15zRPC9K55NE0WbEyOsY3m0KFz-HuSDatncWLSYvOlcGVdysKlF3JXYWIjQ7tEI4V76WA9UMoi-fr9vEEdWLF5C1uWZJOz_S72sQ3G1BzsLp3HyWe9ZN5EBK9mhXzYNv2rONYrr0UJeBmNnMf2mU3sH71OO_G6JvRl5fwFSLSYx8nQs82PhfVhx50wRuWl_zyeCCDy_ytLzjRBvZwKuI9iVIxgM1pRfKG15NWMHfl0lcYnjm7f1_WFGKtVddkLOTICK0_FPtef1L8A16ozo_2NA32WD9PstdcTuD37XbZ6AFXUAZFoZLfCEW97mtIZBY2uYMwDQtc6Nme4o3Ya-MnBEIAs9Vi9d5a4pkf7Two-xjI-9ESgVz79YqL-_OnecQPNJ9yAFtJuxQ7StfsCIZx84hh5VdcZmW9jlezRHh4hTAjsNmrOBFTAjPyaXk98Se3Fj0Ev3bChod63og4frE7_fE7HnoBKVPHRAdBhJ2yrAiPymfij_kD4ke1Vb0AxmGGOwRP2K3TZNqEdKcq89lU6lHYV2UfrWchuF3u4ieNEC1BGu1_m_c55f0YZH1FAq6evCyA0JnFuXzO4cCxC7WHzXXRGSC9Lm3LF7cbaZAgFj5d34gbgUQmJst8nPlpW-KtwRL-pHC6mipunCBv9bU harbor.sysdig-demo.zone/sysdig/agent:9.7.0 || true",
							},
							Env: []corev1.EnvVar{
								{
									Name: "SYSDIG_SECURE_API_TOKEN",
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
