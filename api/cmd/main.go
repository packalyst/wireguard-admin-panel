package main

import (
	"log"
	"net/http"

	"api/internal/adguard"
	"api/internal/auth"
	"api/internal/config"
	"api/internal/database"
	"api/internal/docker"
	"api/internal/firewall"
	"api/internal/geolocation"
	"api/internal/headscale"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/settings"
	"api/internal/setup"
	"api/internal/traefik"
	"api/internal/vpn"
	"api/internal/wireguard"
)

func main() {
	// Load endpoint configuration
	configPath := helper.GetEnv("CONFIG_PATH")
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Loaded configuration v%s with %d services", cfg.Version, len(cfg.Services))

	// Create router
	r := router.New(cfg)

	// Data directory for persistent storage
	dataDir := helper.GetEnv("DATA_DIR")

	// Initialize shared database
	if _, err := database.Init(dataDir); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Initialize encryption (must be before services that use encryption)
	helper.InitEncryption()

	// Initialize and register services
	// Auth must be first (other services depend on it)
	if config.IsServiceEnabled("auth") {
		authSvc, err := auth.New()
		if err != nil {
			log.Printf("Warning: Failed to initialize auth service: %v", err)
		} else {
			auth.SetService(authSvc) // Store instance for other packages
			r.RegisterService("auth", authSvc.Handlers())

			// Register auth validator for middleware
			router.SetAuthValidator(func(token string) bool {
				_, err := authSvc.ValidateSession(token)
				return err == nil
			})

			log.Println("Auth service registered")
		}
	}

	// Setup service (depends on auth for encryption)
	if config.IsServiceEnabled("setup") {
		setupSvc := setup.New()
		r.RegisterService("setup", setupSvc.Handlers())
		log.Println("Setup service registered")
	}

	// Settings service (depends on auth for encryption)
	if config.IsServiceEnabled("settings") {
		settingsSvc := settings.New()
		r.RegisterService("settings", settingsSvc.Handlers())
		log.Println("Settings service registered")

		// Set up Headscale config provider for helper package
		helper.SetHeadscaleConfigProvider(func() (*helper.HeadscaleConfig, error) {
			url, err := settings.GetSetting("headscale_api_url")
			if err != nil {
				return nil, err
			}
			apiKey, err := settings.GetSettingEncrypted("headscale_api_key")
			if err != nil {
				return nil, err
			}
			return &helper.HeadscaleConfig{
				URL:    helper.NormalizeHeadscaleURL(url),
				APIKey: apiKey,
			}, nil
		})
	}

	// Geolocation service (must be before firewall, as firewall depends on it)
	if config.IsServiceEnabled("geolocation") {
		geoSvc, err := geolocation.New(dataDir + "/geolocation")
		if err != nil {
			log.Printf("Warning: Failed to initialize geolocation service: %v", err)
		} else {
			geolocation.SetService(geoSvc)
			r.RegisterService("geolocation", geoSvc.Handlers())
			log.Println("Geolocation service registered")
		}
	}

	if config.IsServiceEnabled("firewall") {
		fwSvc, err := firewall.New(dataDir)
		if err != nil {
			log.Printf("Warning: Failed to initialize firewall service: %v", err)
		} else {
			r.RegisterService("firewall", fwSvc.Handlers())
			log.Println("Firewall service registered")
		}
	}

	if config.IsServiceEnabled("wireguard") {
		wgSvc, err := wireguard.New(dataDir + "/wireguard")
		if err != nil {
			log.Printf("Warning: Failed to initialize wireguard service: %v", err)
		} else {
			wireguard.SetService(wgSvc) // Store instance for other packages
			r.RegisterService("wireguard", wgSvc.Handlers())
			log.Println("WireGuard service registered")
		}
	}

	if config.IsServiceEnabled("traefik") {
		traefikSvc := traefik.New()
		r.RegisterService("traefik", traefikSvc.Handlers())
		log.Println("Traefik service registered")
	}

	if config.IsServiceEnabled("headscale") {
		headscaleSvc := headscale.New()
		r.RegisterService("headscale", headscaleSvc.Handlers())
		log.Println("Headscale service registered")
	}

	if config.IsServiceEnabled("adguard") {
		adguardSvc := adguard.New()
		r.RegisterService("adguard", adguardSvc.Handlers())
		log.Println("AdGuard service registered")
	}

	if config.IsServiceEnabled("docker") {
		dockerSvc := docker.New()
		r.RegisterService("docker", dockerSvc.Handlers())
		log.Println("Docker service registered")
	}

	if config.IsServiceEnabled("vpn") {
		vpnSvc := vpn.New()
		r.RegisterService("vpn", vpnSvc.Handlers())
		log.Println("VPN ACL service registered")
	}

	// Build router
	handler := r.Build()

	// Start server
	port := helper.GetEnv("API_PORT")
	log.Printf("Unified API server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
