-- KumoMTA Configuration for VPN Admin Panel
local kumo = require 'kumo'

local MAIL_DOMAIN = os.getenv('MAIL_DOMAIN') or 'localhost'
local DKIM_SELECTOR = os.getenv('DKIM_SELECTOR') or 'mail'
local DKIM_KEY_PATH = '/var/lib/kumomta/dkim/' .. MAIL_DOMAIN .. '.key'

-- Initialize
kumo.on('init', function()
  -- Use Unbound resolver for proper MX lookups
  -- When name_servers is omitted, Unbound resolves via root nameservers
  kumo.dns.configure_unbound_resolver {
    options = {
      validate = false,  -- Don't require DNSSEC validation
    },
  }

  -- SMTP listener
  kumo.start_esmtp_listener {
    listen = '0.0.0.0:25',
    relay_hosts = { '0.0.0.0/0' },
  }

  -- HTTP API
  kumo.start_http_listener {
    listen = '0.0.0.0:8000',
  }

  -- Spool
  kumo.define_spool {
    name = 'data',
    path = '/var/spool/kumomta/data',
  }
  kumo.define_spool {
    name = 'meta',
    path = '/var/spool/kumomta/meta',
  }

  -- Logging
  kumo.configure_local_logs {
    log_dir = '/var/spool/kumomta/logs',
  }
end)

-- Message received - just accept, KumoMTA routes automatically
kumo.on('smtp_server_message_received', function(msg)
  -- Optional DKIM signing
  local f = io.open(DKIM_KEY_PATH, 'r')
  if f then
    f:close()
    local signer = kumo.dkim.rsa_sha256_signer {
      domain = MAIL_DOMAIN,
      selector = DKIM_SELECTOR,
      key = DKIM_KEY_PATH,
    }
    msg:dkim_sign(signer)
  end
  -- Don't set queue meta - let KumoMTA route by recipient domain
end)

-- Minimal queue config
kumo.on('get_queue_config', function(domain, tenant, campaign, routing_domain)
  return kumo.make_queue_config {
    egress_pool = 'pool0',
  }
end)

-- Egress pool
kumo.on('get_egress_pool', function(pool_name)
  return kumo.make_egress_pool {
    name = pool_name,
    entries = {
      { name = 'source0' },
    },
  }
end)

-- Egress source
kumo.on('get_egress_source', function(source_name)
  return kumo.make_egress_source {
    name = source_name,
  }
end)

-- Egress path
kumo.on('get_egress_path_config', function(routing_domain, egress_source, site_name)
  return kumo.make_egress_path {
    enable_tls = 'OpportunisticInsecure',
  }
end)
