package scanner

import (
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure/mocks"
)

var (
	lastSyncTs        = time.Date(2019, time.November, 15, 23, 54, 05, 0, time.UTC)
	lastSyncFormatted = "2019-11-15T23:54:05Z"
)

var _ = Describe("BaseAdapter", func() {
	var (
		controller  *gomock.Controller
		client      *mocks.MockClient
		baseAdapter Adapter
	)

	BeforeEach(func() {
		controller = gomock.NewController(GinkgoT())
		client = mocks.NewMockClient(controller)
		baseAdapter = NewBackendAdapter(client)
	})

	AfterEach(func() {
		controller.Finish()
	})

	Context("when retrieving metadata", func() {
		It("queries Sysdig Secure when was last time vulnerability db was updated", func() {
			client.EXPECT().GetFeeds().Return(feeds(), nil)

			result, _ := baseAdapter.GetMetadata()

			Expect(result.Properties["harbor.scanner-adapter/vulnerability-database-updated-at"]).To(Equal(lastSyncFormatted))
		})

		Context("and already have a value", func() {
			It("only queries Sysdig Secure once", func() {
				client.EXPECT().GetFeeds().Return(feeds(), nil)

				baseAdapter.GetMetadata()
				result, _ := baseAdapter.GetMetadata()

				Expect(result.Properties["harbor.scanner-adapter/vulnerability-database-updated-at"]).To(Equal(lastSyncFormatted))
			})
		})

		Context("when Secure returns an error getting the feeds", func() {
			It("returns the error", func() {
				client.EXPECT().GetFeeds().Return([]secure.Feed{}, errSecure)

				_, err := baseAdapter.GetMetadata()

				Expect(err).To(MatchError(errSecure))
			})
		})
	})
})

func feeds() []secure.Feed {
	return []secure.Feed{
		{
			Groups: []secure.FeedGroup{
				{
					LastSync: time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
				},
				{
					LastSync: time.Date(2009, time.November, 15, 23, 0, 0, 0, time.UTC),
				},
			},
		},
		{
			Groups: []secure.FeedGroup{
				{
					LastSync: time.Date(2012, time.November, 10, 23, 0, 0, 0, time.UTC),
				},
				{
					LastSync: lastSyncTs,
				},
			},
		},
	}
}
