package ztlab.authz

import future.keywords.if

# Default deny — the entire point of this file is that access is denied
# unless every condition below is explicitly satisfied.
default allow := false
default reason := "denied: no matching allow rule"

# --- Freshness window for /sensitive re-auth requirement (Phase 5) ---
sensitive_reauth_window_seconds := 300  # 5 minutes

# --- Auth time validity ---
# auth_time=0 means "not set" (e.g. lab tests, legacy tokens) — treat as
# a valid session without stale-session penalties.
valid_auth_time if {
	input.user.auth_time > 0
}

# Seconds since the user's last authentication event
seconds_since_auth := result if {
	valid_auth_time
	now := time.now_ns() / 1000000000
	result := now - input.user.auth_time
}

fresh_auth if {
	seconds_since_auth <= sensitive_reauth_window_seconds
}

# --- Continuous authentication: session age thresholds ---
# Session age in hours — used for risk-based step-up decisions.
# Only evaluated when auth_time is a real timestamp (>0).
session_age_hours := result if {
	valid_auth_time
	now := time.now_ns() / 1000000000
	result := (now - input.user.auth_time) / 3600
}

# --- Risk scoring for continuous authentication ---
# Stale session (> 8 hours) requires step-up for sensitive paths
stale_session if {
	session_age_hours > 8
}

# Very stale session (> 24 hours) requires step-up for ALL paths
very_stale_session if {
	session_age_hours > 24
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
	not startswith(input.path, "/sensitive")
	not very_stale_session
}

# --- Allow rule: /sensitive additionally needs a fresh re-auth ---
allow if {
	base_ok
	startswith(input.path, "/sensitive")
	fresh_auth
}

# --- Deny rule: very stale sessions blocked everywhere ---
reason := "denied: session too old (>24h), full re-authentication required" if {
	base_ok
	very_stale_session
}

# --- Deny rule: stale sessions blocked from sensitive paths ---
reason := "denied: session stale (>8h), step-up re-auth required for sensitive" if {
	base_ok
	stale_session
	not fresh_auth
	startswith(input.path, "/sensitive")
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
	startswith(input.path, "/sensitive")
	not fresh_auth
	not stale_session
}

reason := "allowed" if {
	allow
}
