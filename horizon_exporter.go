//https://txvdivcsvip/rest/swagger-ui/index.html

package main

import (
	"crypto/tls"
	"horizon_exporter/collector"
	"net/http"
	"os"
	"os/user"
	"runtime"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

func init() {
	prometheus.MustRegister(versioncollector.NewCollector("horizon_exporter"))
}

func main() {
	var (
		horizonConfig      = &collector.HorizonConfig{}
		insecureSkipVerify = kingpin.Flag("tls.insecure", "Disable TLS certificate validation.").Default("false").Bool()
		metricsPath        = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default("/metrics").String()
		//maxRequests = kingpin.Flag(
		//	"web.max-requests",
		//	"Maximum number of parallel scrape requests. Use 0 to disable.",
		//).Default("40").Int()
		maxProcs = kingpin.Flag(
			"runtime.gomaxprocs", "The target number of CPUs Go will run on (GOMAXPROCS)",
		).Envar("GOMAXPROCS").Default("1").Int()
		toolkitFlags = kingpinflag.AddFlags(kingpin.CommandLine, ":9181")
	)

	kingpin.Flag("horizon.domain", "Vmware Horizon user domain").StringVar(&horizonConfig.Domain)
	kingpin.Flag("horizon.username", "Vmware Horizon user name").StringVar(&horizonConfig.Username)
	kingpin.Flag("horizon.password", "Vmware Horizon user password").StringVar(&horizonConfig.Password)
	kingpin.Flag("horizon.endpoint", "Endpoint to a Horizon Server which has the SDK path enabled.").Default("http://localhost/rest").URLVar(&horizonConfig.Endpoint)
	kingpin.Flag("horizon.timeout", "Defines the timeout for the underlying HTTP client.").Default("10s").DurationVar(&horizonConfig.Timeout)
	kingpin.Flag("horizon.discoveryInterval", "Vmware Horizon inventory discovery interval. Discovery will occur per scrape if set to 0.").Default("15m").DurationVar(&horizonConfig.DiscoveryInterval)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("node_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting horizon_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())
	if user, err := user.Current(); err == nil && user.Uid == "0" {
		level.Warn(logger).Log("msg", "Horizon Exporter is running as root user. This exporter is designed to run as unprivileged user, root is not required.")
	}
	runtime.GOMAXPROCS(*maxProcs)
	level.Debug(logger).Log("msg", "Go MAXPROCS", "procs", runtime.GOMAXPROCS(0))

	if *insecureSkipVerify {
		http.DefaultTransport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		level.Warn(logger).Log("msg", "TLS certificate validation is disabled.")
	}

	hc, err := collector.NewHorizonCollector(horizonConfig, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create Horizon collector", "err", err)
	}

	prometheus.MustRegister(hc)

	http.Handle(*metricsPath, promhttp.Handler())

	server := &http.Server{}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}
