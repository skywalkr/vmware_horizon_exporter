// Package collector includes all individual collectors to gather and export system metrics.
package collector

import (
	"context"
	"fmt"
	passwordcredentials "horizon_exporter/oauth2"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/skywalkr/gohorizon/v8"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

// Namespace defines the common namespace to be used by all metrics.
const namespace = "vhorizon"

var (
	collDesc = map[string]*prometheus.Desc{
		"scrape_success":  prometheus.NewDesc(prometheus.BuildFQName(namespace, "scrape", "collector_success"), "Whether the collector succeeded.", []string{}, nil),
		"scrape_duration": prometheus.NewDesc(prometheus.BuildFQName(namespace, "scrape", "collector_duration_seconds"), "Duration of the collector scrape.", []string{}, nil),
	}

	connServerDesc = map[string]*prometheus.Desc{
		"info": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "info"),
			"A metric with a constant '1' value labeled by build, pod name, name, id, status, and version",
			[]string{"horizon_pod_name", "horizon_connection_server_name", "id", "status", "version"}, nil,
		),
		"connections": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "connection_count"),
			"Number of active connections to the connection server.",
			[]string{"horizon_pod_name", "horizon_connection_server_name"}, nil,
		),
		"tunnel_connections": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "tunneled_connection_count"),
			"Number of connections tunneled through connection server.",
			[]string{"horizon_pod_name", "horizon_connection_server_name"}, nil,
		),
		"service_status": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "service_status"),
			"Status of connection server related Windows services.",
			[]string{"horizon_pod_name", "horizon_connection_server_name", "name", "status"}, nil,
		),
		"protocol_sessions": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "session_count"),
			"Details of connected sessions.",
			[]string{"horizon_pod_name", "horizon_connection_server_name", "protocol"}, nil,
		),
		"addomain_status": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "addomain_status"),
			"Status of the AD domain with respect to connection server.",
			[]string{"horizon_pod_name", "horizon_connection_server_name", "dns_name", "status"}, nil,
		),
		"samlauth_status": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "connserver", "samlauth_status"),
			"Status of the SAML authenticator with respect to connection server.",
			[]string{"horizon_pod_name", "horizon_connection_server_name", "label", "status"}, nil,
		),
	}

	desktPoolDesc = map[string]*prometheus.Desc{
		"info": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "desktpool", "info"),
			"A metric with a constant '1' value labeled by pod name, name, id, source, type, and user assignment",
			[]string{"horizon_pod_name", "horizon_desktop_pool_name", "id", "source", "type", "user_assignment"}, nil,
		),
		"machines": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "desktpool", "machine_count"),
			"Number of machines in the desktop pool.",
			[]string{"horizon_pod_name", "horizon_desktop_pool_name", "state"}, nil,
		),
		"sessions": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "desktpool", "session_count"),
			"Number of connected sessions of the desktop pool.",
			[]string{"horizon_pod_name", "horizon_desktop_pool_name"}, nil,
		),
	}

	gtwyServerDesc = map[string]*prometheus.Desc{
		"info": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gateway", "info"),
			"A metric with a constant '1' value labeled by pod name, name, host, id, status, type, and version",
			[]string{"horizon_pod_name", "horizon_gateway_name", "host", "id", "status", "type", "version"}, nil,
		),
		"connections": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "gateway", "connection_count"),
			"Number of active connections to the gateway",
			[]string{"horizon_pod_name", "horizon_gateway_name", "protocol"}, nil,
		),
	}

	licenseDesc = map[string]*prometheus.Desc{
		"info": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "license", "info"),
			"A metric with a constant '1' value labeled by pod name, mode, health, and usage model",
			[]string{"horizon_pod_name", "mode", "health", "usage_model"}, nil,
		),
		"earliest_expiry": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "license", "earliest_expiry"),
			"Last license or subscription expiry in unixtime",
			[]string{"horizon_pod_name"}, nil,
		),
		"usage_collaborators_total": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "license", "usage_collaborators_total"),
			"Total number of users that are connected to a collaborative session, including the session owner and any collaborators",
			[]string{"horizon_pod_name"}, nil,
		),
		"usage_concurrent_connections_total": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "license", "usage_concurrent_connections_total"),
			"Concurrent connection user count",
			[]string{"horizon_pod_name"}, nil,
		),
		"usage_concurrent_sessions_total": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "license", "usage_concurrent_sessions_total"),
			"Concurrent session count",
			[]string{"horizon_pod_name"}, nil,
		),
		"usage_named_users_total": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "license", "usage_named_users_total"),
			"Number of unique users that have accessed the Horizon environment since the Horizon deployment was first configured or since the last Named Users Count reset",
			[]string{"horizon_pod_name"}, nil,
		),
	}

	localDesc = map[string]*prometheus.Desc{
		"sessions": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "local", "sessions_count"),
			"Summary of the locally resourced sessions in the environment",
			[]string{"horizon_pod_name", "type", "state"}, nil,
		),
	}

	vcenterDesc = map[string]*prometheus.Desc{
		"info": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "vcenter", "info"),
			"A metric with a constant '1' value labeled by pod name, name, id, and version",
			[]string{"horizon_pod_name", "server_name", "id", "version"}, nil,
		),
	}
)

//type horizonScrapeData struct {}

type HorizonConfig struct {
	Domain            string
	Username          string
	Password          string
	Endpoint          *url.URL
	Timeout           time.Duration
	DiscoveryInterval time.Duration
}

type HorizonInventory struct {
	connServers []gohorizon.ConnectionServerInfoV2
	pods        []gohorizon.PodInfo
	pools       []gohorizon.DesktopPoolInfoV2
	sites       []gohorizon.SiteInfo

	localPod  *gohorizon.PodInfo
	localSite *gohorizon.SiteInfo

	lastDiscovered time.Time
}

// HorizonCollector implements the prometheus.Collector interface.
type HorizonCollector struct {
	ac           *gohorizon.APIClient
	config       *HorizonConfig
	logger       log.Logger
	inventory    *HorizonInventory
	inventoryMux sync.Mutex
	//scrapeData   *horizonScrapeData
}

// NewHorizonCollector creates a new HorizonCollector.
func NewHorizonCollector(config *HorizonConfig, logger log.Logger) (*HorizonCollector, error) {
	pwcConfig := passwordcredentials.Config{
		Domain:   config.Domain,
		Username: config.Username,
		Password: config.Password,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/login", config.Endpoint),
			TokenURL: fmt.Sprintf("%s/refresh", config.Endpoint),
		},
	}

	ctx := context.Background()
	conf := gohorizon.NewConfiguration()
	conf.HTTPClient = pwcConfig.Client(ctx)
	conf.Servers[0].URL = config.Endpoint.String()

	return &HorizonCollector{ac: gohorizon.NewAPIClient(conf), config: config, logger: logger, inventory: &HorizonInventory{}}, nil
}

// Collect implements the prometheus.Collector interface.
func (hc HorizonCollector) Collect(ch chan<- prometheus.Metric) {
	begin := time.Now()
	var success float64
	ctx := context.Background()

	//hc.scrapeData = &horizonScrapeData{}

	hc.inventoryMux.Lock()
	if begin.Sub(hc.inventory.lastDiscovered) > hc.config.DiscoveryInterval {
		if err := hc.discover(ctx); err != nil {
			level.Error(hc.logger).Log("msg", "discovery failed", "duration_seconds", time.Since(begin), "err", err)
		} else {
			level.Debug(hc.logger).Log("msg", "discovery succeeded", "duration_seconds", time.Since(begin))
			hc.inventory.lastDiscovered = time.Now()
		}
	}
	hc.inventoryMux.Unlock()

	begin = time.Now()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return hc.collectADDomainMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectConnectionServerMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectDesktopPoolMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectGatewayMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectLicenseMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectSAMLAuthenticatorMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectSessionMetrics(ctx, ch)
	})
	g.Go(func() error {
		return hc.collectVirtualCenterMetrics(ctx, ch)
	})

	err := g.Wait()
	duration := time.Since(begin).Seconds()

	if err != nil {
		level.Error(hc.logger).Log("msg", "collector failed", "duration_seconds", duration, "err", err)
		success = 0
	} else {
		level.Debug(hc.logger).Log("msg", "collector succeeded", "duration_seconds", duration)
		success = 1
	}
	ch <- prometheus.MustNewConstMetric(collDesc["scrape_duration"], prometheus.GaugeValue, duration)
	ch <- prometheus.MustNewConstMetric(collDesc["scrape_success"], prometheus.GaugeValue, success)
}

// Describe implements the prometheus.Collector interface.
func (hc *HorizonCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collDesc["scrape_duration"]
	ch <- collDesc["scrape_success"]

	for key := range localDesc {
		ch <- localDesc[key]
	}

	for key := range connServerDesc {
		ch <- connServerDesc[key]
	}

	for key := range desktPoolDesc {
		ch <- desktPoolDesc[key]
	}

	for key := range gtwyServerDesc {
		ch <- gtwyServerDesc[key]
	}

	for key := range licenseDesc {
		ch <- licenseDesc[key]
	}

	for key := range vcenterDesc {
		ch <- vcenterDesc[key]
	}
}

func (hc *HorizonCollector) discover(ctx context.Context) error {
	level.Debug(hc.logger).Log("msg", "discovery starting")
	defer level.Debug(hc.logger).Log("msg", "discovery complete")

	ctx1, cancel1 := context.WithTimeout(ctx, hc.config.Timeout)
	defer cancel1()

	pods, _, err := hc.ac.FederationAPI.ListPods(ctx1).Execute()

	if err != nil {
		return err
	}

	hc.inventory.pods = pods

	for _, pod := range hc.inventory.pods {
		if *pod.LocalPod {
			hc.inventory.localPod = &pod
		}
	}

	ctx2, cancel2 := context.WithTimeout(ctx, hc.config.Timeout)
	defer cancel2()
	sites, _, err := hc.ac.FederationAPI.ListSites(ctx2).Execute()

	if err != nil {
		return err
	}

	hc.inventory.sites = sites
	hc.inventory.localSite = &hc.inventory.sites[slices.IndexFunc(hc.inventory.sites, func(o gohorizon.SiteInfo) bool { return *o.Id == *hc.inventory.localPod.SiteId })]

	ctx3, cancel3 := context.WithTimeout(ctx, hc.config.Timeout)
	defer cancel3()
	pools, _, err := hc.ac.InventoryAPI.ListDesktopPoolsV2(ctx3).Execute()

	if err != nil {
		return err
	}

	hc.inventory.pools = pools

	ctx4, cancel4 := context.WithTimeout(ctx, hc.config.Timeout)
	defer cancel4()

	connServers, _, err := hc.ac.ConfigAPI.ListConnectionServersV2(ctx4).Execute()

	if err != nil {
		return err
	}

	hc.inventory.connServers = connServers

	return nil
}

func (hc *HorizonCollector) collectADDomainMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.MonitorAPI.ListADDomainMonitorInfosV3(ctx1).Execute()
	if err != nil {
		return err
	}

	for _, item := range items {
		for _, subItem := range item.ConnectionServers {
			ch <- prometheus.MustNewConstMetric(
				connServerDesc["addomain_status"],
				prometheus.GaugeValue,
				1,
				*hc.inventory.localPod.Name,
				*subItem.Name,
				*item.DnsName,
				*subItem.Status,
			)
		}
	}

	return nil
}

func (hc *HorizonCollector) collectConnectionServerMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.MonitorAPI.ListConnectionServerMonitors(ctx1).Execute()

	if err != nil {
		return err
	}

	// API returns limited information when status is unknown so we have to loop thru inventory to find the problematic server
	for _, connSrv := range hc.inventory.connServers {
		var status = "UNKNOWN"

		for _, item := range items {
			if item.Name != nil && *item.Name == *connSrv.Name {
				status = *item.Status

				ch <- prometheus.MustNewConstMetric(
					connServerDesc["connections"],
					prometheus.GaugeValue,
					float64(*item.ConnectionCount),
					*hc.inventory.localPod.Name,
					*connSrv.Name,
				)

				ch <- prometheus.MustNewConstMetric(
					connServerDesc["tunnel_connections"],
					prometheus.GaugeValue,
					float64(*item.TunnelConnectionCount),
					*hc.inventory.localPod.Name,
					*connSrv.Name,
				)

				for _, subItem := range item.Services {
					ch <- prometheus.MustNewConstMetric(
						connServerDesc["service_status"],
						prometheus.GaugeValue,
						1,
						*hc.inventory.localPod.Name,
						*connSrv.Name,
						*subItem.ServiceName,
						*subItem.Status,
					)
				}

				for _, subItem := range item.SessionProtocolData {
					ch <- prometheus.MustNewConstMetric(
						connServerDesc["protocol_sessions"],
						prometheus.GaugeValue,
						float64(*subItem.SessionCount),
						*hc.inventory.localPod.Name,
						*connSrv.Name,
						*subItem.SessionProtocol,
					)
				}

				break
			}
		}

		ch <- prometheus.MustNewConstMetric(
			connServerDesc["info"],
			prometheus.GaugeValue,
			1,
			*hc.inventory.localPod.Name,
			*connSrv.Name,
			*connSrv.Id,
			status,
			*connSrv.Version,
		)
	}

	return nil
}

func (hc *HorizonCollector) collectDesktopPoolMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()

	ids := make([]string, len(hc.inventory.pools))
	for i, item := range hc.inventory.pools {
		ids[i] = *item.Id
	}

	req := hc.ac.MonitorAPI.ListDesktopPoolMetrics(ctx1)
	req = req.Ids(ids)
	items, _, err := req.Execute()

	if err != nil {
		return err
	}

	ctx2, cancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel2()

	req2 := hc.ac.InventoryAPI.ListMachines(ctx2)
	items2, _, err := req2.Execute()

	if err != nil {
		return err
	}

	for _, item := range items {
		desktPool := &hc.inventory.pools[slices.IndexFunc(hc.inventory.pools, func(o gohorizon.DesktopPoolInfoV2) bool { return *o.Id == *item.Id })]
		desktPoolStates := make(map[string]int, 30)

		for _, item2 := range items2 {
			if strings.Compare(*item.Id, *item2.DesktopPoolId) == 0 {
				desktPoolStates[*item2.State] += 1
			}
		}

		ch <- prometheus.MustNewConstMetric(
			desktPoolDesc["info"],
			prometheus.GaugeValue,
			1,
			*hc.inventory.localPod.Name,
			*desktPool.Name,
			*desktPool.Id,
			*desktPool.Source,
			*desktPool.Type,
			*desktPool.UserAssignment,
		)

		for key, value := range desktPoolStates {
			ch <- prometheus.MustNewConstMetric(
				desktPoolDesc["machines"],
				prometheus.GaugeValue,
				float64(value),
				*hc.inventory.localPod.Name,
				*desktPool.Name,
				key,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			desktPoolDesc["sessions"],
			prometheus.GaugeValue,
			float64(*item.NumConnectedSessions),
			*hc.inventory.localPod.Name,
			*desktPool.Name,
		)
	}

	return nil
}

func (hc *HorizonCollector) collectGatewayMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.MonitorAPI.ListGatewayMonitorInfoV2(ctx1).Execute()
	if err != nil {
		return err
	}

	for _, item := range items {
		ch <- prometheus.MustNewConstMetric(
			gtwyServerDesc["info"],
			prometheus.GaugeValue,
			1,
			*hc.inventory.localPod.Name,
			*item.Name,
			*item.Details.Address,
			*item.Id,
			*item.Status,
			*item.Details.Type,
			*item.Details.Version,
		)

		ch <- prometheus.MustNewConstMetric(
			gtwyServerDesc["connections"],
			prometheus.GaugeValue,
			float64(*item.BlastConnectionCount),
			*hc.inventory.localPod.Name,
			*item.Name,
			"BLAST",
		)

		ch <- prometheus.MustNewConstMetric(
			gtwyServerDesc["connections"],
			prometheus.GaugeValue,
			float64(*item.PcoipConnectionCount),
			*hc.inventory.localPod.Name,
			*item.Name,
			"PCOIP",
		)
	}

	return nil
}

func (hc *HorizonCollector) collectLicenseMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.ConfigAPI.ListLicensesV2(ctx1).Execute()
	if err != nil {
		return err
	}

	var expiry int64 = 0
	var health string = "GREEN"
	if *items[0].LicenseMode == "SUBSCRIPTION" {
		expiry = *items[0].ExpirationTime
		health = *items[0].LicenseHealth
	}

	ch <- prometheus.MustNewConstMetric(
		licenseDesc["info"],
		prometheus.GaugeValue,
		1,
		*hc.inventory.localPod.Name,
		*items[0].LicenseMode,
		health,
		*items[0].UsageModel,
	)

	ch <- prometheus.MustNewConstMetric(
		licenseDesc["earliest_expiry"],
		prometheus.GaugeValue,
		float64(expiry),
		*hc.inventory.localPod.Name,
	)

	return nil
}

func (hc *HorizonCollector) collectSAMLAuthenticatorMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.MonitorAPI.ListSAMLAuthenticatorMonitorsV2(ctx1).Execute()
	if err != nil {
		return err
	}

	for _, item := range items {
		for _, subItem := range item.ConnectionServers {
			ch <- prometheus.MustNewConstMetric(
				connServerDesc["samlauth_status"],
				prometheus.GaugeValue,
				1,
				*hc.inventory.localPod.Name,
				*subItem.Name,
				*item.Details.Label,
				*subItem.Status,
			)
		}
	}

	return nil
}

func (hc *HorizonCollector) collectSessionMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.InventoryAPI.ListSessionInfo(ctx1).Execute()
	if err != nil {
		return err
	}

	i := map[string]map[string]int{"APPLICATION": {"ACTIVE": 0, "DISCONNECTED": 0, "IDLE": 0, "PENDING": 0}, "DESKTOP": {"ACTIVE": 0, "DISCONNECTED": 0, "IDLE": 0, "PENDING": 0}}
	for _, item := range items {
		i[*item.SessionType][*item.SessionState] += 1

		if *item.SessionState == "CONNECTED" {
			if *item.IdleDuration > 0 {
				i[*item.SessionType]["IDLE"] += 1
			}
		}
	}

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["APPLICATION"]["CONNECTED"]-i["APPLICATION"]["IDLE"]),
		*hc.inventory.localPod.Name,
		"APPLICATION",
		"ACTIVE",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["APPLICATION"]["DISCONNECTED"]),
		*hc.inventory.localPod.Name,
		"APPLICATION",
		"DISCONNECTED",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["APPLICATION"]["IDLE"]),
		*hc.inventory.localPod.Name,
		"APPLICATION",
		"IDLE",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["APPLICATION"]["PENDING"]),
		*hc.inventory.localPod.Name,
		"APPLICATION",
		"PENDING",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["DESKTOP"]["CONNECTED"]-i["DESKTOP"]["IDLE"]),
		*hc.inventory.localPod.Name,
		"DESKTOP",
		"ACTIVE",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["DESKTOP"]["DISCONNECTED"]),
		*hc.inventory.localPod.Name,
		"DESKTOP",
		"DISCONNECTED",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["DESKTOP"]["IDLE"]),
		*hc.inventory.localPod.Name,
		"DESKTOP",
		"IDLE",
	)

	ch <- prometheus.MustNewConstMetric(
		localDesc["sessions"],
		prometheus.GaugeValue,
		float64(i["DESKTOP"]["PENDING"]),
		*hc.inventory.localPod.Name,
		"DESKTOP",
		"PENDING",
	)

	return nil
}

func (hc *HorizonCollector) collectVirtualCenterMetrics(ctx context.Context, ch chan<- prometheus.Metric) error {
	ctx1, cancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel1()
	items, _, err := hc.ac.ConfigAPI.ListVCInfoV2(ctx1).Execute()
	if err != nil {
		return err
	}

	for _, item := range items {
		ch <- prometheus.MustNewConstMetric(
			vcenterDesc["info"],
			prometheus.GaugeValue,
			1,
			*hc.inventory.localPod.Name,
			*item.ServerName,
			*item.Id,
			*item.Version,
		)
	}

	return nil
}
