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
	configMap    = "a-configmap"
	secret       = "a-secret"
	resourceName = "inline-scan-d3892b65b81bb8b7cac3cc346f7aec8b"
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
		inlineAdapter = scanner.NewInlineAdapter(client, k8sClient, namespace, configMap, secret)
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
								"docker login harbor.sysdig-demo.zone -u '$(HARBOR_ROBOTACCOUNT_USER)' -p '$(HARBOR_ROBOTACCOUNT_PASSWORD)' && (/bin/inline_scan.sh analyze -k '$(SYSDIG_SECURE_API_TOKEN)' -P harbor.sysdig-demo.zone/sysdig/agent:9.7.0 || true )",
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
