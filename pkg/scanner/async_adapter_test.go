package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
	scannermocks "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner/mocks"
)

const (
	asyncAdapterRefreshRate = 100 * time.Millisecond
)

var _ = Describe("Async-Adapter", func() {
	var (
		adapter         *AsyncAdapter
		ctxCancelFunc   context.CancelFunc
		mocksController *gomock.Controller
		wrappedAdapter  *scannermocks.MockAdapter
	)

	BeforeEach(func() {
		log.SetOutput(GinkgoWriter)
		ctx := context.TODO()
		mocksController = gomock.NewController(GinkgoT())
		wrappedAdapter = scannermocks.NewMockAdapter(mocksController)
		ctx, ctxCancelFunc = context.WithCancel(ctx)
		adapter = NewAsyncAdapter(ctx, wrappedAdapter, log.StandardLogger(), asyncAdapterRefreshRate)
	})

	AfterEach(func() {
		ctxCancelFunc()
		mocksController.Finish()
	})

	When("when requesting scanning of an image", func() {
		request := scanRequest()

		Context("the response from the underlying wrapped adapter is correct", func() {
			expResponse := harbor.ScanResponse{ID: scanID}

			It("successfully returns the scanID created by the underlying wrapped adapter", func() {
				wrappedAdapter.EXPECT().Scan(request).Return(expResponse, nil)
				response, err := adapter.Scan(request)
				Expect(response).To(Equal(expResponse))
				Expect(err).To(BeNil())
			})
			It("adds an entry to the internal results cache to keep track of the request", func() {
				wrappedAdapter.EXPECT().Scan(request).Return(expResponse, nil)
				_, _ = adapter.Scan(request)
				adapter.lock.RLock()
				cacheElem, cacheHit := adapter.results[scanID]
				adapter.lock.RUnlock()
				Expect(cacheHit).To(BeTrue())
				Expect(cacheElem).To(BeNil())
			})
			It("creates a background task that checks for the report status at a given cadence", func() {
				wrappedAdapter.EXPECT().Scan(request).Return(expResponse, nil)
				wrappedAdapter.EXPECT().GetVulnerabilityReport(expResponse.ID).Return(harbor.VulnerabilityReport{}, ErrVulnerabilityReportNotReady).MinTimes(1)
				_, _ = adapter.Scan(request)
				time.Sleep(asyncAdapterRefreshRate * 2)
			})
		})

		Context("the response from the underlying wrapped adapter is not correct", func() {
			expResponse := harbor.ScanResponse{}
			expError := fmt.Errorf("some error")

			It("returns the same result to the caller", func() {
				wrappedAdapter.EXPECT().Scan(request).Return(expResponse, expError)
				response, err := adapter.Scan(request)
				Expect(response).To(Equal(expResponse))
				Expect(err).To(Equal(expError))
			})

			It("completely skip its processing", func() {
				wrappedAdapter.EXPECT().Scan(request).Return(expResponse, expError)
				wrappedAdapter.EXPECT().GetVulnerabilityReport(expResponse.ID).Return(harbor.VulnerabilityReport{}, ErrScanRequestIDNotFound).MaxTimes(0)

				_, _ = adapter.Scan(request)
				time.Sleep(asyncAdapterRefreshRate * 2)

				adapter.lock.RLock()
				cacheElem, cacheHit := adapter.results[scanID]
				adapter.lock.RUnlock()
				Expect(cacheHit).To(BeFalse())
				Expect(cacheElem).To(BeNil())
			})
		})
	})

	When("when getting the vulnerability report", func() {
		request := scanRequest()
		scanRequestResponse := harbor.ScanResponse{ID: scanID}

		Context("the report creation request was never issued", func() {
			It("returns a not-found error", func() {
				res, err := adapter.GetVulnerabilityReport(scanID)
				Expect(res).To(Equal(harbor.VulnerabilityReport{}))
				Expect(err).To(MatchError(ErrScanRequestIDNotFound))
			})
			It("does not call the underlying wrapped adapter at all", func() {
				wrappedAdapter.EXPECT().GetVulnerabilityReport(scanID).MaxTimes(0)
				res, err := adapter.GetVulnerabilityReport(scanID)
				Expect(res).To(Equal(harbor.VulnerabilityReport{}))
				Expect(err).To(MatchError(ErrScanRequestIDNotFound))
			})
		})

		Context("report creation is still on-going", func() {
			BeforeEach(func() {
				wrappedAdapter.EXPECT().Scan(request).Return(scanRequestResponse, nil)
			})

			It("returns not-ready error", func() {
				wrappedAdapter.EXPECT().GetVulnerabilityReport(scanRequestResponse.ID).Return(harbor.VulnerabilityReport{}, ErrVulnerabilityReportNotReady).AnyTimes()
				_, _ = adapter.Scan(request)
				time.Sleep(asyncAdapterRefreshRate * 6)
				_, err := adapter.GetVulnerabilityReport(scanRequestResponse.ID)
				Expect(err).To(MatchError(ErrVulnerabilityReportNotReady))
			})
			It("exists a background task that checks for the report status at a given cadence", func() {
				wrappedAdapter.EXPECT().GetVulnerabilityReport(scanRequestResponse.ID).Return(harbor.VulnerabilityReport{}, ErrVulnerabilityReportNotReady).MinTimes(5)
				_, _ = adapter.Scan(request)
				_, _ = adapter.GetVulnerabilityReport(scanRequestResponse.ID)
				time.Sleep(asyncAdapterRefreshRate * 6)
			})
		})

		Context("report creation is complete", func() {
			BeforeEach(func() {
				wrappedAdapter.EXPECT().Scan(request).Return(scanRequestResponse, nil)
			})

			Context("the report has already been retrieved", func() {
				It("successfully return the report result with no error", func() {
					expResponse := harbor.VulnerabilityReport{Scanner: &harbor.Scanner{Name: "my-scanner"}}
					wrappedAdapter.EXPECT().GetVulnerabilityReport(scanRequestResponse.ID).Return(expResponse, nil)
					_, _ = adapter.Scan(request)
					time.Sleep(asyncAdapterRefreshRate * 2)

					res, err := adapter.GetVulnerabilityReport(scanRequestResponse.ID)
					Expect(res).To(Equal(expResponse))
					Expect(err).To(BeNil())
				})
				It("successfully return an empty report with the causing error", func() {
					expResponse, expError := harbor.VulnerabilityReport{}, fmt.Errorf("my-custom-error")
					wrappedAdapter.EXPECT().GetVulnerabilityReport(scanRequestResponse.ID).Return(expResponse, expError)
					_, _ = adapter.Scan(request)
					time.Sleep(asyncAdapterRefreshRate * 2)

					res, err := adapter.GetVulnerabilityReport(scanRequestResponse.ID)
					Expect(res).To(Equal(expResponse))
					Expect(err).To(Equal(expError))
				})
				It("removes the returned report from the internal results cache", func() {
					expResponse := harbor.VulnerabilityReport{Scanner: &harbor.Scanner{Name: "my-scanner"}}
					wrappedAdapter.EXPECT().GetVulnerabilityReport(scanRequestResponse.ID).Return(expResponse, nil)
					_, _ = adapter.Scan(request)

					time.Sleep(asyncAdapterRefreshRate * 2)
					_, _ = adapter.GetVulnerabilityReport(scanRequestResponse.ID)
					time.Sleep(asyncAdapterRefreshRate)

					adapter.lock.RLock()
					cacheResult, cacheHit := adapter.results[scanRequestResponse.ID]
					adapter.lock.RUnlock()

					Expect(cacheResult).To(BeNil())
					Expect(cacheHit).To(BeFalse())
				})
			})
			Context("the report is being retrieved", func() {
				It("waits for the complete retrieval of the report from the underlying wrapped adapter", func() {
					expResponse := harbor.VulnerabilityReport{Scanner: &harbor.Scanner{Name: "my-scanner"}}
					retrievalDuration := 10 * time.Second
					wrappedAdapter.EXPECT().GetVulnerabilityReport(scanRequestResponse.ID).DoAndReturn(func(scanID harbor.ScanRequestID) (harbor.VulnerabilityReport, error) {
						time.Sleep(retrievalDuration)
						return expResponse, nil
					})
					_, _ = adapter.Scan(request)

					time.Sleep(retrievalDuration + (asyncAdapterRefreshRate * 2))
					res, err := adapter.GetVulnerabilityReport(scanRequestResponse.ID)
					Expect(res).To(Equal(expResponse))
					Expect(err).To(BeNil())
				})
			})
		})

	})
})
