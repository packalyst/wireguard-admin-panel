-- KumoMTA Configuration for VPN Admin Panel
-- Handles DKIM signing and outbound email delivery

local kumo = require 'kumo'
local utils = require 'policy-extras.policy_utils'

-- Get environment variables
local MAIL_DOMAIN = os.getenv('MAIL_DOMAIN') or 'localhost'
local DKIM_SELECTOR = os.getenv('DKIM_SELECTOR') or 'mail'
local DKIM_KEY_PATH = '/opt/kumomta/etc/dkim/' .. MAIL_DOMAIN .. '.key'

-- Initialize KumoMTA
kumo.on('init', function()
  -- SMTP listener for local relay (from API container)
  kumo.start_esmtp_listener {
    listen = '0.0.0.0:25',
    relay_hosts = { '0.0.0.0/0' },  -- Allow relay from any host (secured by Docker network)
  }

  -- HTTP listener for management API
  kumo.start_http_listener {
    listen = '0.0.0.0:8000',
  }

  -- Configure logging
  kumo.configure_local_logs {
    log_dir = '/var/spool/kumomta/logs',
    max_file_size = 10000000,  -- 10MB
  }

  -- Define DKIM signer
  kumo.define_signer {
    name = 'dkim_signer',
    domain = MAIL_DOMAIN,
    selector = DKIM_SELECTOR,
    headers = { 'From', 'To', 'Subject', 'Date', 'MIME-Version', 'Content-Type' },
    key = DKIM_KEY_PATH,
  }
end)

-- Message reception hook
kumo.on('smtp_server_message_received', function(msg)
  -- Get sender domain
  local sender = msg:from_header().address
  local sender_domain = string.match(sender, '@(.+)$') or MAIL_DOMAIN

  -- Sign with DKIM if sending from our domain
  if sender_domain == MAIL_DOMAIN then
    msg:dkim_sign(kumo.get_signer('dkim_signer'))
  end

  -- Queue for delivery
  msg:set_meta('queue', 'outbound')
end)

-- Delivery configuration
kumo.on('get_queue_config', function(domain, tenant, campaign)
  return kumo.make_queue_config {
    max_age = '24 hours',
    retry_interval = '5 minutes',
    max_retry_interval = '1 hour',
  }
end)

-- SMTP client configuration for outbound delivery
kumo.on('get_egress_path_config', function(domain)
  return kumo.make_egress_path {
    connection_limit = 10,
    enable_tls = 'OpportunisticInsecure',
    max_message_rate = '100/minute',
  }
end)

-- Source configuration
kumo.on('get_egress_source', function(msg)
  return kumo.make_egress_source {
    name = 'default',
  }
end)

print('KumoMTA initialized for domain: ' .. MAIL_DOMAIN)
