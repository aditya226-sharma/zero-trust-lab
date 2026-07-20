package ztlab.authz

import future.keywords.if

# Default deny — the entire point of this file is that access is denied
# unless every condition below is explicitly satisfied.
default allow := false
default reason := "denied: no matching allow rule"

# --- Freshness window for /sensitive re-auth requirement (Phase 5) ---
sensitive_reauth_window_seconds := 300  # 5 minutes

# Seconds since the user's last authentication event
seconds_since_auth := result if {
	now := time.now_ns() / 1000000000
	result := now - input.user.auth_time
}

fresh_auth if {
	seconds_since_auth <= sensitive_reauth_window_seconds
}

# --- Core identity + posture gate, applies to every path ---
base_ok if {
	input.user.authenticated == true
	input.user.mfa_verified == true
	input.device.posture == "healthy"
}

# --- Allow rule: public paths just need base identity+posture ---
allow if {
	base_ok
	input.path != "/sensitive"
}

# --- Allow rule: /sensitive additionally needs a fresh re-auth ---
allow if {
	base_ok
	input.path == "/sensitive"
	fresh_auth
}

# --- Human-readable deny reasons, useful in logs and in Phase 7 testing ---
reason := "denied: user not authenticated" if {
	not input.user.authenticated
}

reason := "denied: mfa not verified" if {
	input.user.authenticated
	not input.user.mfa_verified
}

reason := "denied: device posture unhealthy" if {
	input.user.authenticated
	input.user.mfa_verified
	input.device.posture != "healthy"
}

reason := "denied: sensitive path requires re-auth within 5 minutes" if {
	base_ok
	input.path == "/sensitive"
	not fresh_auth
}

reason := "allowed" if {
	allow
}
