package scanner_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

		It("creates the namespace where jobs are going to be triggered", func() {
			inlineAdapter.Scan(scanRequest())

			result, _ := k8sClient.CoreV1().Namespaces().Get(context.Background(), namespace, v1.GetOptions{})

			Expect(result.Name).To(Equal(namespace))
		})

		It("creates a secret with the authentication data within namespace", func() {
			inlineAdapter.Scan(scanRequest())

			storedUser, storedPassword := getUserAndPasswordFromSecret(k8sClient, namespace, resourceName)

			Expect(storedUser).To(Equal(user))
			Expect(storedPassword).To(Equal(password))
		})

		It("schedules the scanning job within namespace", func() {
			inlineAdapter.Scan(scanRequest())

			result, _ := k8sClient.BatchV1().Jobs(namespace).Get(context.Background(), resourceName, v1.GetOptions{})

			Expect(result.Name).To(Equal(resourceName))
		})
	})
})

func getUserAndPasswordFromSecret(k8sClient kubernetes.Interface, namespace string, name string) (string, string) {
	secret, _ := k8sClient.CoreV1().Secrets(namespace).Get(context.Background(), name, v1.GetOptions{})

	var parsed map[string]interface{}
	json.Unmarshal(secret.Data["config.json"], &parsed)

	encodedCredentials := parsed["auths"].(map[string]interface{})["harbor.sysdig-demo.zone"].(map[string]interface{})["auth"].(string)
	basicAuthCredentials, _ := base64.StdEncoding.DecodeString(encodedCredentials)
	credentials := strings.Split(string(basicAuthCredentials), ":")

	return credentials[0], credentials[1]
}
