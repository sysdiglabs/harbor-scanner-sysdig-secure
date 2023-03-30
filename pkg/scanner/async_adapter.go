package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/harbor"
)

const (
	DefaultAsyncAdapterRefreshRate = 20 * time.Second
)

var _ Adapter = &AsyncAdapter{}

// AsyncAdapter is just a wrapper of the underlying real adapter (e.g. inlineAdapter) whose only goal is to make all the long-running operations non-blocking.
type AsyncAdapter struct {
	consumptionChan     chan harbor.ScanRequestID // channel where complete consumption of a report will be published, so it can be safely deleted from the results cache
	internalRefreshRate time.Duration
	lock                sync.RWMutex // mutex to sync access to the internal results map
	log                 Logger
	requestsChan        chan harbor.ScanRequestID // channel where new requests about reports will be published
	repliesChan         chan *asyncReportReply    // channel where replies about retrieval of reports will be published
	results             map[harbor.ScanRequestID]*asyncReportReply
	stopChan            chan struct{} // channel where stop signal will be published so that all the background tasks can stop running
	wrapped             Adapter
}

type asyncReportReply struct {
	scanID harbor.ScanRequestID
	report harbor.VulnerabilityReport
	err    error
}

func NewAsyncAdapter(ctx context.Context, toWrap Adapter, logger Logger, refreshRate time.Duration) *AsyncAdapter {
	adapter := &AsyncAdapter{
		internalRefreshRate: refreshRate,
		lock:                sync.RWMutex{},
		log:                 logger,
		requestsChan:        make(chan harbor.ScanRequestID),
		repliesChan:         make(chan *asyncReportReply),
		consumptionChan:     make(chan harbor.ScanRequestID),
		stopChan:            make(chan struct{}),
		results:             make(map[harbor.ScanRequestID]*asyncReportReply),
		wrapped:             toWrap,
	}

	adapter.listen(ctx)
	return adapter
}

func (a *AsyncAdapter) GetMetadata() (harbor.ScannerAdapterMetadata, error) {
	return a.wrapped.GetMetadata()
}

func (a *AsyncAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	resp, err := a.wrapped.Scan(req)
	if err == nil && resp.ID != "" {
		a.requestsChan <- resp.ID
		go a.awaitReportAvailability(resp.ID) //we spawn a background task that checks report creation status with a given cadence
	}
	return resp, err
}

func (a *AsyncAdapter) GetVulnerabilityReport(scanID harbor.ScanRequestID) (harbor.VulnerabilityReport, error) {
	a.lock.RLock()
	reportResult, ok := a.results[scanID]
	a.lock.RUnlock()

	if ok {
		// the report is still not ready and processing is ongoing
		if reportResult == nil {
			return harbor.VulnerabilityReport{}, ErrVulnerabilityReportNotReady
		}

		// report is complete, so we notify its consumption and return the result
		a.consumptionChan <- reportResult.scanID
		return reportResult.report, reportResult.err
	}

	// we never received a scan request with that specific ID because otherwise we will always have a hit on the internal results cache
	return harbor.VulnerabilityReport{}, ErrScanRequestIDNotFound
}

func (a *AsyncAdapter) awaitReportAvailability(scanID harbor.ScanRequestID) {
	ticker := time.NewTicker(a.internalRefreshRate)
	for {
		select {
		case <-a.stopChan:
			a.log.Debugf("Stopping async task of '%s'", scanID)
			ticker.Stop()
			return
		case <-ticker.C:
			a.log.Infof("Checking status of report '%s'", scanID)
			report, err := a.wrapped.GetVulnerabilityReport(scanID)
			if err != ErrVulnerabilityReportNotReady {
				ticker.Stop()
				a.repliesChan <- &asyncReportReply{scanID: scanID, report: report, err: err}
				return
			}
		}
	}
}

func (a *AsyncAdapter) listen(ctx context.Context) {

	go func(ctx context.Context) {
		a.log.Infof("Start listening for async updates")
		for {
			select {
			case <-ctx.Done():
				a.log.Infof("Stop listening for updates: sending signal to stop background tasks")
				a.stopChan <- struct{}{}
				return
			case id := <-a.consumptionChan:
				a.log.Debugf("Received consumption for report '%s', deleting it from cache", id)
				a.lock.Lock()
				delete(a.results, id)
				a.lock.Unlock()
				a.log.Debugf("report '%s' deleted from cache", id)
			case id := <-a.requestsChan:
				a.log.Debugf("Received new request for report '%s', adding it to cache", id)
				a.lock.Lock()
				a.results[id] = nil
				a.lock.Unlock()
				a.log.Debugf("Report '%s' added to cache", id)
			case reply := <-a.repliesChan:
				if reply != nil {
					a.log.Infof("Report '%s' completed, updating cache", reply.scanID)
					a.lock.Lock()
					a.results[reply.scanID] = reply
					a.lock.Unlock()
					a.log.Debugf("Report '%s' updated in cache", reply.scanID)
				}
			}
		}
	}(ctx)
}
