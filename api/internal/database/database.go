package database

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

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

// Get returns the shared database instance
func Get() *sql.DB {
	return instance
}

// createSchema creates all required tables (if they don't exist)
func createSchema(db *sql.DB) error {
	// Existing firewall tables (preserved from firewall.db)
	firewallSchema := `
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
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS blocked_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		jail_name TEXT,
		reason TEXT,
		blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		hit_count INTEGER DEFAULT 1,
		manual BOOLEAN DEFAULT 0,
		UNIQUE(ip, jail_name)
	);

	CREATE TABLE IF NOT EXISTS attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_ip TEXT NOT NULL,
		dest_port INTEGER,
		protocol TEXT,
		jail_name TEXT,
		action TEXT
	);

	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT NOT NULL,
		dest_ip TEXT NOT NULL,
		dest_port INTEGER,
		protocol TEXT,
		domain TEXT
	);

	CREATE TABLE IF NOT EXISTS allowed_ports (
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		essential BOOLEAN DEFAULT 0,
		service TEXT,
		PRIMARY KEY (port, protocol)
	);

	CREATE TABLE IF NOT EXISTS blocked_countries (
		country_code TEXT PRIMARY KEY,
		name TEXT,
		direction TEXT DEFAULT 'inbound' CHECK(direction IN ('inbound', 'both')),
		enabled BOOLEAN DEFAULT 1,
		status TEXT DEFAULT 'active' CHECK(status IN ('active', 'adding', 'removing')),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS country_zones_cache (
		country_code TEXT PRIMARY KEY,
		zones TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (country_code) REFERENCES blocked_countries(country_code) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
	CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(expires_at);
	CREATE INDEX IF NOT EXISTS idx_blocked_ips_jail ON blocked_ips(jail_name);
	CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON attempts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(source_ip);
	CREATE INDEX IF NOT EXISTS idx_attempts_jail ON attempts(jail_name);
	CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_traffic_client_ip ON traffic_logs(client_ip);
	CREATE INDEX IF NOT EXISTS idx_traffic_dest_ip ON traffic_logs(dest_ip);
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
	// Add service column to allowed_ports if it doesn't exist
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('allowed_ports') WHERE name='service'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE allowed_ports ADD COLUMN service TEXT`)
		if err != nil {
			return fmt.Errorf("failed to add service column: %v", err)
		}
		log.Printf("Migration: added 'service' column to allowed_ports")
	}

	// Add CIDR/range support columns to blocked_ips
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('blocked_ips') WHERE name='is_range'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE blocked_ips ADD COLUMN is_range BOOLEAN DEFAULT 0`)
		if err != nil {
			return fmt.Errorf("failed to add is_range column: %v", err)
		}
		log.Printf("Migration: added 'is_range' column to blocked_ips")
	}

	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('blocked_ips') WHERE name='escalated_from'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE blocked_ips ADD COLUMN escalated_from TEXT`)
		if err != nil {
			return fmt.Errorf("failed to add escalated_from column: %v", err)
		}
		log.Printf("Migration: added 'escalated_from' column to blocked_ips")
	}

	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('blocked_ips') WHERE name='source'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE blocked_ips ADD COLUMN source TEXT DEFAULT 'manual'`)
		if err != nil {
			return fmt.Errorf("failed to add source column: %v", err)
		}
		log.Printf("Migration: added 'source' column to blocked_ips")
	}

	// Add escalation settings columns to jails
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('jails') WHERE name='escalate_enabled'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE jails ADD COLUMN escalate_enabled BOOLEAN DEFAULT 0`)
		if err != nil {
			return fmt.Errorf("failed to add escalate_enabled column: %v", err)
		}
		log.Printf("Migration: added 'escalate_enabled' column to jails")
	}

	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('jails') WHERE name='escalate_threshold'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE jails ADD COLUMN escalate_threshold INTEGER DEFAULT 3`)
		if err != nil {
			return fmt.Errorf("failed to add escalate_threshold column: %v", err)
		}
		log.Printf("Migration: added 'escalate_threshold' column to jails")
	}

	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('jails') WHERE name='escalate_window'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE jails ADD COLUMN escalate_window INTEGER DEFAULT 3600`)
		if err != nil {
			return fmt.Errorf("failed to add escalate_window column: %v", err)
		}
		log.Printf("Migration: added 'escalate_window' column to jails")
	}

	// Add raw_data column to vpn_clients for storing full client data
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('vpn_clients') WHERE name='raw_data'`).Scan(&count)
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
	// snapshot_all -> selected, allow_all_future -> allow_all
	_, err = db.Exec(`UPDATE vpn_clients SET acl_policy = 'selected' WHERE acl_policy = 'snapshot_all'`)
	if err != nil {
		log.Printf("Migration warning: could not update snapshot_all policies: %v", err)
	}
	_, err = db.Exec(`UPDATE vpn_clients SET acl_policy = 'allow_all' WHERE acl_policy = 'allow_all_future'`)
	if err != nil {
		log.Printf("Migration warning: could not update allow_all_future policies: %v", err)
	}

	// Add country column to traffic_logs for geolocation
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('traffic_logs') WHERE name='country'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE traffic_logs ADD COLUMN country TEXT DEFAULT ''`)
		if err != nil {
			return fmt.Errorf("failed to add country column: %v", err)
		}
		log.Printf("Migration: added 'country' column to traffic_logs")
	}

	// Add status column to blocked_countries if it doesn't exist
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('blocked_countries') WHERE name='status'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE blocked_countries ADD COLUMN status TEXT DEFAULT 'active'`)
		if err != nil {
			return fmt.Errorf("failed to add status column: %v", err)
		}
		log.Printf("Migration: added 'status' column to blocked_countries")
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
