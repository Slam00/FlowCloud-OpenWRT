//go:build linux

// flowcloudd routes selected domains and subnets of an OpenWrt router through
// WARP and other tunnels. See README.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"flowcloud-openwrt/internal/daemon"
	"flowcloud-openwrt/internal/lists"
)

var version = "dev"

const usage = `usage: flowcloudd <command>

  run            run the service (used by /etc/init.d/flowcloud)
  status [-json] show tunnels, sections and DNS counters
  update-lists   download the section lists now
  presets        print the community lists as JSON
  version        print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command, args := os.Args[1], os.Args[2:]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	configName := flags.String("config", "flowcloud", "UCI config name")
	stateDir := flags.String("state", "/etc/flowcloud", "persistent state directory")
	runDir := flags.String("rundir", "/var/run/flowcloud", "runtime directory")
	asJSON := flags.Bool("json", false, "print JSON")
	_ = flags.Parse(args)

	switch command {
	case "run":
		log.SetFlags(0)
		log.SetPrefix("")
		run(*configName, *stateDir, *runDir)
	case "status":
		status(*runDir, *asJSON)
	case "update-lists":
		signalDaemon(*runDir, syscall.SIGUSR1)
	case "presets":
		printPresets()
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func run(configName, stateDir, runDir string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reload := make(chan struct{}, 1)
	update := make(chan struct{}, 1)
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGUSR1)
	go func() {
		for received := range signals {
			target := reload
			if received == syscall.SIGUSR1 {
				target = update
			}
			select {
			case target <- struct{}{}:
			default:
			}
		}
	}()
	log.Printf("flowcloudd %s starting", version)
	d := daemon.New(daemon.Options{ConfigName: configName, StateDir: stateDir, RunDir: runDir, Version: version})
	if err := d.Run(ctx, daemon.Signals{Reload: reload, UpdateLists: update}); err != nil {
		log.Fatal(err)
	}
	log.Printf("flowcloudd stopped")
}

func signalDaemon(runDir string, sig syscall.Signal) {
	data, err := os.ReadFile(filepath.Join(runDir, "flowcloudd.pid"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowcloudd is not running")
		os.Exit(1)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid pid file")
		os.Exit(1)
	}
	if err := syscall.Kill(pid, sig); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func status(runDir string, asJSON bool) {
	data, err := os.ReadFile(daemon.StatusPath(runDir))
	if err != nil {
		if asJSON {
			fmt.Println(`{"running":false}`)
			return
		}
		fmt.Println("flowcloudd is not running")
		return
	}
	if asJSON {
		fmt.Println(string(data))
		return
	}
	var s daemon.Status
	if err := json.Unmarshal(data, &s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	state := "stopped"
	if s.Running {
		state = "running"
	}
	fmt.Printf("FlowCloud %s: %s\n", s.Version, state)
	if s.Error != "" {
		fmt.Printf("error: %s\n", s.Error)
	}
	for _, warning := range s.Warnings {
		fmt.Printf("warning: %s\n", warning)
	}
	fmt.Println("\nTunnels:")
	for _, t := range s.Tunnels {
		ping := "-"
		if t.PingMs >= 0 {
			ping = fmt.Sprintf("%d ms", t.PingMs)
		}
		fmt.Printf("  %-12s %-9s %-10s %-10s %-22s %-8s %s\n", t.Name, t.Type, t.Device, t.State, t.Endpoint, ping, t.Profile)
		if t.Error != "" {
			fmt.Printf("  %-12s error: %s\n", "", t.Error)
		}
	}
	fmt.Println("\nSections:")
	for _, section := range s.Sections {
		target := section.Action
		if section.Action == "tunnel" {
			target = "-> " + section.Tunnel
		}
		enabled := ""
		if !section.Enabled {
			enabled = " (disabled)"
		}
		fmt.Printf("  %-16s %-14s domains %-7d subnets %-6d%s\n", section.Name, target, section.Domains, section.Subnets, enabled)
		for _, missing := range section.Missing {
			fmt.Printf("  %-16s missing: %s\n", "", missing)
		}
	}
	fmt.Printf("\nDNS %s: %d queries, %d routed, %d addresses learned, %d failures\n",
		s.DNS.Listen, s.DNS.Queries, s.DNS.Matched, s.DNS.Learned, s.DNS.Failures)
	if s.ListsUpdated > 0 {
		fmt.Printf("Lists updated %s\n", time.Unix(s.ListsUpdated, 0).Format("2006-01-02 15:04"))
	}
	for _, listError := range s.ListErrors {
		fmt.Printf("  list error: %s\n", listError)
	}
}

func printPresets() {
	type preset struct {
		Name    string `json:"name"`
		Label   string `json:"label"`
		Subnets bool   `json:"subnets"`
	}
	var result []preset
	for _, p := range lists.Presets() {
		result = append(result, preset{Name: p.Name, Label: p.Label, Subnets: p.Subnets != ""})
	}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
}
