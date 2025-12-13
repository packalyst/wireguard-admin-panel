-- KumoMTA Configuration for VPN Admin Panel
-- Simple relay config for sending notifications

local kumo = require 'kumo'

local MAIL_DOMAIN = os.getenv('MAIL_DOMAIN') or 'localhost'
local DKIM_SELECTOR = os.getenv('DKIM_SELECTOR') or 'mail'
local DKIM_KEY_PATH = '/var/lib/kumomta/dkim/' .. MAIL_DOMAIN .. '.key'

print('KumoMTA starting for domain: ' .. MAIL_DOMAIN)

-- Initialize listeners
kumo.on('init', function()
  -- Configure DNS resolver explicitly
  kumo.dns.configure_resolver {
    name_servers = { '8.8.8.8:53', '1.1.1.1:53' },
  }

  -- SMTP listener for local relay
  kumo.start_esmtp_listener {
    listen = '0.0.0.0:25',
    relay_hosts = { '0.0.0.0/0' },
  }

  -- HTTP API listener
  kumo.start_http_listener {
    listen = '0.0.0.0:8000',
  }

  -- Configure spool
  kumo.define_spool {
    name = 'data',
    path = '/var/spool/kumomta/data',
  }

  kumo.define_spool {
    name = 'meta',
    path = '/var/spool/kumomta/meta',
  }

  -- Enable logging
  kumo.configure_local_logs {
    log_dir = '/var/spool/kumomta/logs',
    max_segment_duration = '1 minute',
  }
end)

-- Helper to check if file exists
local function file_exists(path)
  local f = io.open(path, 'r')
  if f then
    f:close()
    return true
  end
  return false
end

-- Handle incoming messages
kumo.on('smtp_server_message_received', function(msg)
  -- DKIM sign if key exists
  if file_exists(DKIM_KEY_PATH) then
    local signer = kumo.dkim.rsa_sha256_signer {
      domain = MAIL_DOMAIN,
      selector = DKIM_SELECTOR,
      key = DKIM_KEY_PATH,
    }
    msg:dkim_sign(signer)
  end

  msg:set_meta('queue', 'default')
end)

-- Queue configuration
kumo.on('get_queue_config', function(domain, tenant, campaign, routing_domain)
  return kumo.make_queue_config {
    egress_pool = 'default',
  }
end)

-- Egress pool
kumo.on('get_egress_pool', function(pool_name)
  return kumo.make_egress_pool {
    name = pool_name,
    entries = {
      { name = 'default' },
    },
  }
end)

-- Egress source
kumo.on('get_egress_source', function(source_name)
  return kumo.make_egress_source {
    name = source_name,
  }
end)

-- Egress path config (how to deliver)
kumo.on('get_egress_path_config', function(routing_domain, egress_source, site_name)
  return kumo.make_egress_path {
    enable_tls = 'OpportunisticInsecure',
  }
end)

print('KumoMTA initialized for domain: ' .. MAIL_DOMAIN)
