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
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure/mocks"
)

const (
	namespace    = "a-namespace"
	resourceName = "inline-scan-demo-c3lzZGlnL2FnZW50fGFuIGltYWdlIGRpZ2VzdA=="
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
		inlineAdapter = scanner.NewInlineAdapter(client, k8sClient, namespace)
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("when scanning an image", func() {
		It("returns the scanID for checking if scan has finished", func() {
			result, _ := inlineAdapter.Scan(scanRequest())

			Expect(result).To(Equal(harbor.ScanResponse{ID: scanID}))
		})

		It("creates a secret with the authentication data within namespace", func() {
			inlineAdapter.Scan(scanRequest())

			storedUser, storedPassword := getUserAndPasswordFromSecret(k8sClient, namespace, resourceName)

			Expect(storedUser).To(Equal(user))
			Expect(storedPassword).To(Equal(password))
		})

		It("schedules the scanning job within namespace", func() {
			inlineAdapter.Scan(scanRequest())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, metav1.GetOptions{})

			Expect(result).To(Equal(job()))
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
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceName,
			Namespace: namespace,
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
								"sysdig/agent:9.7.0",
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
									SecretName: resourceName,
								},
							},
						},
					},
				},
			},
		},
	}
}
