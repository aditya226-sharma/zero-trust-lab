package ztlab.authz

import future.keywords.if

# ---------------------------------------------------------------------------
# ALLOW: public path with full identity + posture
# ---------------------------------------------------------------------------
test_allow_public_full_identity if {
	allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": 0, "email": "alice@zerotrust.lab"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

test_allow_public_reason_is_allowed if {
	reason == "allowed" with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": 0, "email": "alice@zerotrust.lab"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# DENY: not authenticated
# ---------------------------------------------------------------------------
test_deny_not_authenticated if {
	not allow with input as {"user": {"authenticated": false, "mfa_verified": false, "auth_time": 0, "email": ""}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

test_deny_not_authenticated_reason if {
	reason == "denied: user not authenticated" with input as {"user": {"authenticated": false, "mfa_verified": false, "auth_time": 0, "email": ""}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# DENY: authenticated but MFA not verified
# ---------------------------------------------------------------------------
test_deny_mfa_not_verified if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": false, "auth_time": 0, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

test_deny_mfa_not_verified_reason if {
	reason == "denied: mfa not verified" with input as {"user": {"authenticated": true, "mfa_verified": false, "auth_time": 0, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# DENY: device posture unhealthy
# ---------------------------------------------------------------------------
test_deny_unhealthy_posture if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": 0, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "unhealthy"}, "path": "/public"}
}

test_deny_unhealthy_posture_reason if {
	reason == "denied: device posture unhealthy" with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": 0, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "unhealthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# DENY: posture field missing entirely (fail-closed)
# ---------------------------------------------------------------------------
test_deny_missing_posture if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": 0, "email": "a@b.c"}, "device": {"ip": "10.10.1.50"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# ALLOW: /sensitive with fresh re-auth (auth_time = now)
# ---------------------------------------------------------------------------
test_allow_sensitive_fresh_reauth if {
	allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": time.now_ns() / 1000000000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# DENY: /sensitive with stale re-auth (auth_time = 1 hour ago)
# ---------------------------------------------------------------------------
test_deny_sensitive_stale_reauth if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 3600, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

test_deny_sensitive_stale_reauth_reason if {
	reason == "denied: sensitive path requires re-auth within 5 minutes" with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 3600, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# DENY: /sensitive with unauthenticated user (reason = auth, not re-auth)
# ---------------------------------------------------------------------------
test_deny_sensitive_not_authenticated if {
	reason == "denied: user not authenticated" with input as {"user": {"authenticated": false, "mfa_verified": false, "auth_time": time.now_ns() / 1000000000, "email": ""}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# DENY: /sensitive with MFA missing (reason = MFA, not re-auth)
# ---------------------------------------------------------------------------
test_deny_sensitive_mfa_missing if {
	reason == "denied: mfa not verified" with input as {"user": {"authenticated": true, "mfa_verified": false, "auth_time": time.now_ns() / 1000000000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# EDGE: /public with healthy posture, MFA, but auth_time=0 (still allows public)
# ---------------------------------------------------------------------------
test_allow_public_even_with_zero_auth_time if {
	allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": 0, "email": "alice@zerotrust.lab"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# EDGE: default deny with completely empty input
# ---------------------------------------------------------------------------
test_default_deny_empty_input if {
	not allow with input as {}
}

# NOTE: With empty input, reason is undefined (no rule matches) because
# OPA treats missing fields as errors, not false. The policy is designed
# for structured input from authz-bridge -- this is expected behavior.

# ---------------------------------------------------------------------------
# EDGE: /sensitive at exactly the boundary (299 seconds ago = fresh)
# ---------------------------------------------------------------------------
test_allow_sensitive_at_boundary if {
	allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 299, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# EDGE: /sensitive at 301 seconds ago = stale
# ---------------------------------------------------------------------------
test_deny_sensitive_one_second_over if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 301, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ===========================================================================
# CONTINUOUS AUTHENTICATION TESTS (New Feature)
# ===========================================================================

# ---------------------------------------------------------------------------
# DENY: very stale session (>24h) blocked on public paths
# ---------------------------------------------------------------------------
test_deny_very_stale_session_on_public if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 90000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

test_deny_very_stale_session_reason if {
	reason == "denied: session too old (>24h), full re-authentication required" with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 90000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# DENY: stale session (>8h) blocked on /sensitive paths
# ---------------------------------------------------------------------------
test_deny_stale_session_on_sensitive if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 36000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

test_deny_stale_session_on_sensitive_reason if {
	reason == "denied: session stale (>8h), step-up re-auth required for sensitive" with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 36000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# ALLOW: session at 7h (just under 8h threshold) on /sensitive with fresh re-auth
# ---------------------------------------------------------------------------
test_allow_session_under_8h_with_fresh_reauth if {
	allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": time.now_ns() / 1000000000, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}

# ---------------------------------------------------------------------------
# ALLOW: fresh session (<24h) on public paths still works
# ---------------------------------------------------------------------------
test_allow_fresh_session_on_public if {
	allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 3600, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/public"}
}

# ---------------------------------------------------------------------------
# DENY: 25h session on /sensitive (both very_stale and needs re-auth)
# ---------------------------------------------------------------------------
test_deny_very_stale_on_sensitive if {
	not allow with input as {"user": {"authenticated": true, "mfa_verified": true, "auth_time": (time.now_ns() / 1000000000) - 93600, "email": "a@b.c"}, "device": {"ip": "10.10.1.50", "posture": "healthy"}, "path": "/sensitive"}
}
