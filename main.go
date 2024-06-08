package main

import (
	"bufio"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "wireguard"
)

var (
	addr      = flag.String("a", "/metrics", "URL path for surfacing collected metrics")
	port      = flag.String("p", ":9586", "address for WireGuard exporter")
	config    = flag.String("c", "/etc/wireguard/wg0.conf", "Path to main file config")
	Interface = flag.String("i", "wg0", "Wireguard interface")
)

type peer struct {
	peerName string
	peerKey  string
}

type collector struct {
	bytesReceived *prometheus.Desc
	bytesSent     *prometheus.Desc
	lasthandshake *prometheus.Desc
	counterconfig *prometheus.Desc
}

func newCollector() *collector {
	flag.Parse()
	return &collector{
		bytesReceived: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "bytes_received"),
			"Total number of bytes received.",
			[]string{"interface", "public_key", "name"},
			nil,
		),
		bytesSent: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "bytes_sent"),
			"Total number of bytes sent.",
			[]string{"interface", "public_key", "name"},
			nil,
		),
		lasthandshake: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "last_handshake"),
			"UNIX timestamp seconds of the last handshake",
			[]string{"interface", "public_key", "name"},
			nil,
		),
		counterconfig: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "counter_config"),
			"Configuration counter.",
			[]string{"interface"},
			nil,
		),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesReceived
	ch <- c.bytesSent
	ch <- c.lasthandshake
	ch <- c.counterconfig
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	flag.Parse()
	file, err := os.Open(*config)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	peerNames := make(map[string]peer)
	scanner := bufio.NewScanner(file)
	inBlock := false
	pubKey := ""
	peername := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[Peer]") && !inBlock {
			// log.Println("Found peer block ...")
			inBlock = true
		} else if strings.Contains(line, "AllowedIPs") {
			// log.Println("End of peer block")
			inBlock = false
			peername = ""
		} else if strings.Contains(line, "friendly_name") {
			// log.Println("Found peer name ", strings.Split(line, "=")[1])
			peername = strings.TrimSpace(strings.Split(line, "=")[1])
		} else if strings.Contains(line, "PublicKey") {
			// log.Println("Found public Key", strings.Split(line, "=")[1])
			pubKey = strings.TrimSpace(strings.Split(line, "=")[1]) + "="
			peerNames[pubKey] = peer{peerName: peername, peerKey: pubKey}
		}
	}

	cmd := exec.Command("wg", "show", *Interface, "dump")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running command: %v\n", err)
		return
	}

	dump := strings.Split(string(output), "\n")
	count := 0
	for _, line := range dump[1:] {
		if line == "" {
			continue
		}
		count++
		fields := strings.Fields(line)
		interfaceName := *Interface
		publicKey := fields[0]
		lasthandshake, err := strconv.ParseFloat(fields[4], 64)
		if err != nil {
			log.Println("Error parsing lasthandshake:", err)
			lasthandshake = 0
		}
		// log.Println(peerNames)
		user_name := peerNames[publicKey].peerName
		log.Println("Checking key ", publicKey)
		if user_name == "" {
			log.Println("User name not set for key:", publicKey)
		} else {
			log.Println("User for key: ", publicKey, " is ", user_name)
		}

		bytesReceived, err := strconv.ParseFloat(fields[5], 64)
		if err != nil {
			log.Println("Error parsing bytes received:", err)
			bytesReceived = 0
		}
		bytesSent, err := strconv.ParseFloat(fields[6], 64)
		if err != nil {
			log.Println("Error parsing bytes sent:", err)
			bytesSent = 0
		}
		ch <- prometheus.MustNewConstMetric(
			c.bytesReceived,
			prometheus.CounterValue,
			bytesReceived,
			interfaceName, publicKey, user_name,
		)

		ch <- prometheus.MustNewConstMetric(
			c.bytesSent,
			prometheus.CounterValue,
			bytesSent,
			interfaceName, publicKey, user_name,
		)

		ch <- prometheus.MustNewConstMetric(
			c.lasthandshake,
			prometheus.GaugeValue,
			lasthandshake,
			interfaceName, publicKey, user_name,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.counterconfig,
		prometheus.GaugeValue,
		float64(count),
		*Interface,
	)
}

func main() {
	flag.Parse()
	collector := newCollector()
	prometheus.MustRegister(collector)

	endpoint := http.NewServeMux()
	endpoint.Handle(*addr, promhttp.Handler())

	log.Println("starting WireGuard exporter on ", *port, *addr)
	log.Println("Config path is :", *config)
	log.Println("Interface exporting is :", *Interface)
	s := &http.Server{
		Addr:         *port,
		Handler:      endpoint,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	log.Fatal(s.ListenAndServe())
}
