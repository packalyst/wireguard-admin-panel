package firewall

import (
	"context"
	"log"

	"api/internal/config"
	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"
)

func init() {
	LoadBlocklistSources()
}

// New creates a new firewall service
func New(dataDir string) (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	fwCfg := config.GetFirewallConfig()
	ctx, cancel := context.WithCancel(context.Background())

	svc := &Service{
		db:           db,
		dnsCache:     newLRUDNSCache(dnsCacheMaxSize, dnsCacheTTL),
		jailMonitors: make(map[int64]*jailMonitor),
		ctx:          ctx,
		cancel:       cancel,
		config: Config{
			EssentialPorts:         helper.BuildEssentialPorts(),
			IgnoreNetworks:         helper.ParseStringList(helper.GetEnv("IGNORE_NETWORKS")),
			MaxAttempts:            fwCfg.MaxAttempts,
			MaxTrafficLogs:         fwCfg.MaxTrafficLogs,
			DataDir:                dataDir,
			WgPort:                 helper.GetEnvInt("WG_PORT"),
			WgIPPrefix:             helper.ExtractIPPrefix(helper.GetEnv("WG_IP_RANGE")),
			HeadscaleIPPrefix:      helper.ExtractIPPrefix(helper.GetEnv("HEADSCALE_IP_RANGE")),
			JailCheckInterval:      fwCfg.JailCheckIntervalSec,
			TrafficMonitorInterval: fwCfg.TrafficMonitorIntervalSec,
			CleanupInterval:        fwCfg.CleanupIntervalMin,
			DNSLookupTimeout:       fwCfg.DNSLookupTimeoutSec,
		},
	}

	if err := svc.ensureDefaultJails(); err != nil {
		log.Printf("Warning: Failed to ensure default jails: %v", err)
	}

	if err := svc.ApplyRules(); err != nil {
		log.Printf("Warning: Failed to apply initial firewall rules: %v", err)
	}

	// Start background tasks
	go svc.runJailMonitors()
	go svc.runVPNTrafficMonitor()
	go svc.runExpirationCleanup()

	log.Printf("Firewall service initialized")
	return svc, nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetStatus":           s.handleStatus,
		"GetBlocked":          s.handleGetBlocked,
		"BlockIP":             s.handleBlockIP,
		"UnblockIP":           s.handleUnblockIP,
		"GetAttempts":         s.handleAttempts,
		"GetPorts":            s.handleGetPorts,
		"AddPort":             s.handleAddPort,
		"RemovePort":          s.handleRemovePort,
		"GetJails":            s.handleGetJails,
		"CreateJail":          s.handleCreateJail,
		"GetJail":             s.handleGetJail,
		"UpdateJail":          s.handleUpdateJail,
		"DeleteJail":          s.handleDeleteJail,
		"GetTraffic":          s.handleTraffic,
		"GetTrafficStats":     s.handleTrafficStats,
		"GetTrafficLive":      s.handleTrafficLive,
		"GetConfig":           s.handleGetConfig,
		"UpdateConfig":        s.handleUpdateConfig,
		"ApplyRules":          s.handleApplyRules,
		"GetSSHPort":          s.handleGetSSHPort,
		"ChangeSSHPort":       s.handleChangeSSHPort,
		"GetBlocklists":       s.handleGetBlocklists,
		"ImportBlocklist":     s.handleImportBlocklist,
		"DeleteBlockedSource": s.handleDeleteBlockedSource,
	}
}
