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
	configMap    = "a-configmap"
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
		inlineAdapter = scanner.NewInlineAdapter(client, k8sClient, secureURL, namespace, configMap, secret)
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
								"docker login harbor.sysdig-demo.zone -u '$(HARBOR_ROBOTACCOUNT_USER)' -p '$(HARBOR_ROBOTACCOUNT_PASSWORD)' && (/bin/inline_scan.sh analyze -s 'https://secure.sysdig.com' -k '$(SYSDIG_SECURE_API_TOKEN)' -d 'an image digest' -P harbor.sysdig-demo.zone/sysdig/agent:9.7.0 || true )",
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
								{
									Name: "HARBOR_ROBOTACCOUNT_USER",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: secret,
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
												Name: secret,
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
										Name: configMap,
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

func activeJob() *batchv1.Job {
	job := job()
	job.Status.Active = 1

	return job
}
