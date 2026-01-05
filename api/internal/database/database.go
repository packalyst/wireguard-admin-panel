package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// ErrNotAvailable is returned when the database is not initialized
var ErrNotAvailable = errors.New("database not available")

// DB is the shared database instance
var (
	instance *sql.DB
	once     sync.Once
	dbPath   string
)

// Init initializes the shared database connection
// Database file persists in Docker volume - survives container restarts
func Init(dataDir string) (*sql.DB, error) {
	var initErr error

	once.Do(func() {
		dbPath = dataDir + "/app.db"

		// Open database (creates file if not exists)
		db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %v", err)
			return
		}

		// Create tables if they don't exist
		if err := createSchema(db); err != nil {
			initErr = fmt.Errorf("failed to create schema: %v", err)
			return
		}

		instance = db
		log.Printf("Database initialized at %s", dbPath)
	})

	return instance, initErr
}

// Get returns the shared database instance (for backwards compatibility)
func Get() *sql.DB {
	return instance
}

// GetDB returns the shared database instance or an error if not initialized
func GetDB() (*sql.DB, error) {
	if instance == nil {
		return nil, ErrNotAvailable
	}
	return instance, nil
}

// createSchema creates all required tables (if they don't exist)
func createSchema(db *sql.DB) error {
	// Firewall schema - unified firewall_entries table + supporting tables
	firewallSchema := `
	-- Jail configurations for fail2ban-style blocking
	CREATE TABLE IF NOT EXISTS jails (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN DEFAULT 1,
		log_file TEXT,
		filter_regex TEXT,
		max_retry INTEGER DEFAULT 5,
		find_time INTEGER DEFAULT 600,
		ban_time INTEGER DEFAULT 2592000,
		port TEXT,
		action TEXT DEFAULT 'drop',
		last_log_pos INTEGER DEFAULT 0,
		escalate_enabled BOOLEAN DEFAULT 0,
		escalate_threshold INTEGER DEFAULT 3,
		escalate_window INTEGER DEFAULT 3600,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Connection attempts log (for jail monitoring)
	CREATE TABLE IF NOT EXISTS attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_ip TEXT NOT NULL,
		dest_port INTEGER,
		protocol TEXT,
		jail_name TEXT,
		action TEXT
	);

	-- VPN traffic logs
	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT NOT NULL,
		dest_ip TEXT NOT NULL,
		dest_port INTEGER,
		protocol TEXT,
		domain TEXT,
		country TEXT DEFAULT ''
	);

	-- Country zones cache (IP ranges for country blocking)
	CREATE TABLE IF NOT EXISTS country_zones_cache (
		country_code TEXT PRIMARY KEY,
		zones TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Unified firewall entries table (IPs, ranges, countries, ports)
	CREATE TABLE IF NOT EXISTS firewall_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entry_type TEXT NOT NULL CHECK(entry_type IN ('ip', 'range', 'country', 'port')),
		value TEXT NOT NULL,
		action TEXT DEFAULT 'block' CHECK(action IN ('block', 'allow')),
		direction TEXT DEFAULT 'inbound' CHECK(direction IN ('inbound', 'outbound', 'both')),
		protocol TEXT DEFAULT 'both' CHECK(protocol IN ('tcp', 'udp', 'both')),
		source TEXT DEFAULT 'manual',
		reason TEXT,
		name TEXT,
		essential BOOLEAN DEFAULT 0,
		expires_at DATETIME,
		enabled BOOLEAN DEFAULT 1,
		hit_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON attempts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(source_ip);
	CREATE INDEX IF NOT EXISTS idx_attempts_jail ON attempts(jail_name);
	CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_traffic_client_ip ON traffic_logs(client_ip);
	CREATE INDEX IF NOT EXISTS idx_traffic_dest_ip ON traffic_logs(dest_ip);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_entries_unique ON firewall_entries(entry_type, value, protocol);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_type ON firewall_entries(entry_type);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_enabled ON firewall_entries(enabled);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_expires ON firewall_entries(expires_at);
	CREATE INDEX IF NOT EXISTS idx_firewall_entries_source ON firewall_entries(source);
	`

	// New tables for auth and settings
	appSchema := `
	-- Users table for authentication
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);

	-- Settings table (key-value store)
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT,
		encrypted BOOLEAN DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Sessions table for login tokens
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

	-- Domain routes for Traefik reverse proxy
	CREATE TABLE IF NOT EXISTS domain_routes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		target_ip TEXT NOT NULL,
		target_port INTEGER NOT NULL,
		vpn_client_id INTEGER,
		enabled BOOLEAN DEFAULT 1,
		https_backend BOOLEAN DEFAULT 0,
		middlewares TEXT DEFAULT '[]',
		description TEXT,
		access_mode TEXT DEFAULT 'vpn' CHECK(access_mode IN ('vpn', 'public')),
		frontend_ssl BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (vpn_client_id) REFERENCES vpn_clients(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_domain_routes_domain ON domain_routes(domain);
	CREATE INDEX IF NOT EXISTS idx_domain_routes_client ON domain_routes(vpn_client_id);
	`

	// VPN ACL tables - unified view of all VPN clients and access control
	vpnSchema := `
	-- Unified view of all VPN clients (WireGuard + Headscale)
	CREATE TABLE IF NOT EXISTS vpn_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		ip TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL CHECK(type IN ('wireguard', 'headscale')),
		external_id TEXT,
		raw_data TEXT,
		acl_policy TEXT NOT NULL DEFAULT 'selected' CHECK(acl_policy IN ('block_all', 'selected', 'allow_all')),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- ACL rules between clients (source can reach target)
	CREATE TABLE IF NOT EXISTS vpn_acl_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_client_id INTEGER NOT NULL,
		target_client_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (source_client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE,
		FOREIGN KEY (target_client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE,
		UNIQUE(source_client_id, target_client_id)
	);

	-- VPN router status tracking
	CREATE TABLE IF NOT EXISTS vpn_router_config (
		id INTEGER PRIMARY KEY CHECK(id = 1),
		enabled BOOLEAN DEFAULT 0,
		authkey TEXT,
		headscale_user TEXT DEFAULT 'vpn-router',
		route_id TEXT,
		status TEXT DEFAULT 'disabled',
		last_check DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_vpn_acl_source ON vpn_acl_rules(source_client_id);
	CREATE INDEX IF NOT EXISTS idx_vpn_acl_target ON vpn_acl_rules(target_client_id);
	CREATE INDEX IF NOT EXISTS idx_vpn_clients_type ON vpn_clients(type);
	CREATE INDEX IF NOT EXISTS idx_vpn_clients_external_id ON vpn_clients(external_id);
	`

	// Execute firewall schema
	if _, err := db.Exec(firewallSchema); err != nil {
		return fmt.Errorf("failed to create firewall schema: %v", err)
	}

	// Execute app schema
	if _, err := db.Exec(appSchema); err != nil {
		return fmt.Errorf("failed to create app schema: %v", err)
	}

	// Execute VPN ACL schema
	if _, err := db.Exec(vpnSchema); err != nil {
		return fmt.Errorf("failed to create VPN schema: %v", err)
	}

	// Run migrations for existing databases
	if err := runMigrations(db); err != nil {
		return fmt.Errorf("failed to run migrations: %v", err)
	}

	log.Printf("Database schema up to date")
	return nil
}

// runMigrations handles schema updates for existing databases
func runMigrations(db *sql.DB) error {
	var count int

	// Drop old tables if they exist (clean migration to unified firewall_entries)
	oldTables := []string{"blocked_ips", "blocked_countries", "allowed_ports"}
	for _, table := range oldTables {
		_, _ = db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table))
	}

	// Add raw_data column to vpn_clients for storing full client data
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_clients') WHERE name='raw_data'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE vpn_clients ADD COLUMN raw_data TEXT`)
		if err != nil {
			return fmt.Errorf("failed to add raw_data column: %v", err)
		}
		log.Printf("Migration: added 'raw_data' column to vpn_clients")
	}

	// Migrate old ACL policies to new simplified model
	_, _ = db.Exec(`UPDATE vpn_clients SET acl_policy = 'selected' WHERE acl_policy = 'snapshot_all'`)
	_, _ = db.Exec(`UPDATE vpn_clients SET acl_policy = 'allow_all' WHERE acl_policy = 'allow_all_future'`)

	// Add WireGuard peer columns to vpn_clients for storing encrypted keys
	wgColumns := []struct {
		name string
		def  string
	}{
		{"public_key", "TEXT"},
		{"private_key_enc", "TEXT"},
		{"preshared_key_enc", "TEXT"},
		{"enabled", "INTEGER DEFAULT 1"},
	}
	for _, col := range wgColumns {
		err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_clients') WHERE name=?`, col.name).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			_, err = db.Exec(`ALTER TABLE vpn_clients ADD COLUMN ` + col.name + ` ` + col.def)
			if err != nil {
				return fmt.Errorf("failed to add %s column: %v", col.name, err)
			}
			log.Printf("Migration: added '%s' column to vpn_clients", col.name)
		}
	}

	// Migration: Add middlewares column to domain_routes
	var hasMiddlewares int
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('domain_routes') WHERE name='middlewares'`).Scan(&hasMiddlewares)
	if err != nil {
		return err
	}
	if hasMiddlewares == 0 {
		_, err = db.Exec(`ALTER TABLE domain_routes ADD COLUMN middlewares TEXT DEFAULT '[]'`)
		if err != nil {
			return fmt.Errorf("failed to add middlewares column: %v", err)
		}
		// Migrate vpn_only=1 to middlewares containing vpn-only@file
		_, _ = db.Exec(`UPDATE domain_routes SET middlewares = '["vpn-only@file"]' WHERE vpn_only = 1`)
		log.Printf("Migration: added 'middlewares' column to domain_routes")
	}

	// Migration: Add session tracking columns (ip_address, user_agent, last_active)
	sessionCols := []struct {
		name string
		def  string
	}{
		{"ip_address", "TEXT DEFAULT ''"},
		{"user_agent", "TEXT DEFAULT ''"},
		{"last_active", "DATETIME"},
	}
	for _, col := range sessionCols {
		err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name=?`, col.name).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			_, err = db.Exec(`ALTER TABLE sessions ADD COLUMN ` + col.name + ` ` + col.def)
			if err != nil {
				return fmt.Errorf("failed to add sessions.%s column: %v", col.name, err)
			}
			log.Printf("Migration: added '%s' column to sessions", col.name)
			if col.name == "last_active" {
				_, _ = db.Exec(`UPDATE sessions SET last_active = created_at WHERE last_active IS NULL`)
			}
		}
	}

	// Migration: Add 2FA columns to users table
	twoFACols := []struct {
		name string
		def  string
	}{
		{"totp_secret_enc", "TEXT"},
		{"totp_enabled", "INTEGER DEFAULT 0"},
	}
	for _, col := range twoFACols {
		err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name=?`, col.name).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			_, err = db.Exec(`ALTER TABLE users ADD COLUMN ` + col.name + ` ` + col.def)
			if err != nil {
				return fmt.Errorf("failed to add users.%s column: %v", col.name, err)
			}
			log.Printf("Migration: added '%s' column to users", col.name)
		}
	}

	// Migration: Add access_mode and frontend_ssl columns to domain_routes
	domainRouteCols := []struct {
		name string
		def  string
	}{
		{"access_mode", "TEXT DEFAULT 'vpn'"},
		{"frontend_ssl", "BOOLEAN DEFAULT 0"},
	}
	for _, col := range domainRouteCols {
		err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('domain_routes') WHERE name=?`, col.name).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			_, err = db.Exec(`ALTER TABLE domain_routes ADD COLUMN ` + col.name + ` ` + col.def)
			if err != nil {
				return fmt.Errorf("failed to add domain_routes.%s column: %v", col.name, err)
			}
			log.Printf("Migration: added '%s' column to domain_routes", col.name)
		}
	}

	return nil
}

// Close closes the database connection
func Close() error {
	if instance != nil {
		return instance.Close()
	}
	return nil
}
