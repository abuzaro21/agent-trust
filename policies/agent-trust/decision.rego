# Agent Trust — refund policy decision (Step 8C).
#
# BOUNDARY: Rego decides over VERIFIED FACTS ONLY (docs/architecture.md,
# Policy Plane). It never parses JWS, resolves DIDs, checks status lists,
# touches Redis, or performs I/O — every upstream gate (PoP, VC
# verification, issuer trust, revocation, quarantine, replay) is enforced
# by trusted code before this policy runs, and enters here as trusted
# facts (identity.proofVerified, credential.verified, status.*, replay.*).
#
# DENIAL PRECEDENCE (Step 8F, deterministic — exactly one primary code):
#   1. ACTION_NOT_IN_SCOPE          — action not in delegated actions
#   2. RESOURCE_NOT_IN_SCOPE        — resource not covered by delegation
#   3. AUDIENCE_MISMATCH            — target not in delegated audience
#   4. AUTHORITY_NOT_YET_VALID      — authority window not open
#   5. AUTHORITY_EXPIRED            — authority window closed
#   6. CURRENCY_MISMATCH            — currency differs from delegation
#   7. AUTHORITY_LIMIT_EXCEEDED     — amount above delegated limit
#
# Supported action: refund:create (the P0 demo domain policy).
#
# TIME / WASM PARITY: time.parse_rfc3339_ns is NOT implemented in OPA's
# Wasm runtime (discovered by the wasm parity tests, Step 8M). Authority
# windows are therefore compared as canonical UTC strings — the
# VerifiedFacts schema pins context.now / authority.validFrom /
# authority.validUntil to ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$, where
# lexicographic order IS chronological order. Trusted code assembles these.
package agenttrust

import rego.v1

decision := {"effect": "ALLOW", "reasonCodes": allow_reasons} if {
	refund_action_authorized
	resource_authorized
	audience_authorized
	authority_window_open
	currency_authorized
	amount_authorized
} else := {"effect": "DENY", "reasonCodes": [deny_code]} if {
	count(deny_codes) > 0
	deny_code := deny_codes[0]
} else := {"effect": "DENY", "reasonCodes": ["REQUEST_MALFORMED"]}

# --- the one supported action -------------------------------------------

refund_action_authorized if {
	input.request.action == "refund:create"
	input.request.action in input.authority.actions
}

# --- contextual authority checks ----------------------------------------

resource_authorized if {
	some r in input.authority.resources
	resource_matches(r, input.request.resource)
}

resource_matches(pattern, resource) if {
	endswith(pattern, ":*")
	prefix := substring(pattern, 0, count(pattern) - 1)
	startswith(resource, prefix)
}

resource_matches(pattern, resource) if {
	not endswith(pattern, ":*")
	pattern == resource
}

audience_authorized if {
	not "audience" in object.keys(input.authority) # unconstrained delegation
}

audience_authorized if {
	input.request.audience in input.authority.audience
}

authority_window_open if {
	window_open(input.authority, input.context.now)
}

window_open(authority, now) if {
	not "validFrom" in object.keys(authority)
	not "validUntil" in object.keys(authority)
}

window_open(authority, now) if {
	open_from(authority, now)
	not_closed(authority, now)
}

open_from(authority, now) if {
	not "validFrom" in object.keys(authority)
}

open_from(authority, now) if {
	"validFrom" in object.keys(authority)
	now >= authority.validFrom
}

not_closed(authority, now) if {
	not "validUntil" in object.keys(authority)
}

not_closed(authority, now) if {
	"validUntil" in object.keys(authority)
	now < authority.validUntil
}

currency_authorized if {
	not "currency" in object.keys(object.get(input.authority, "limits", {}))
}

currency_authorized if {
	limits := object.get(input.authority, "limits", {})
	"currency" in object.keys(limits)
	currency := limits.currency
	params := object.get(input.request, "parameters", {})
	object.get(params, "currency", "") == currency
}

amount_authorized if {
	not "amount" in object.keys(object.get(input.authority, "limits", {}))
}

amount_authorized if {
	limits := object.get(input.authority, "limits", {})
	"amount" in object.keys(limits)
	max_amount := limits.amount
	params := object.get(input.request, "parameters", {})
	object.get(params, "amount", -1) <= max_amount
}

# --- deterministic denial precedence (evaluated in order) ----------------

deny_codes := [code |
	some code in [
		denial_action,
		denial_resource,
		denial_audience,
		denial_window,
		denial_currency,
		denial_amount,
	]
	code != null
]

denial_action := null if {
	refund_action_authorized
} else := "ACTION_NOT_IN_SCOPE"

denial_resource := null if {
	resource_authorized
} else := "RESOURCE_NOT_IN_SCOPE"

denial_audience := null if {
	audience_authorized
} else := "AUDIENCE_MISMATCH"

denial_window := null if {
	authority_window_open
} else := denial_window_code

denial_window_code := "AUTHORITY_NOT_YET_VALID" if {
	"validFrom" in object.keys(input.authority)
	input.context.now < input.authority.validFrom
} else := "AUTHORITY_EXPIRED"

denial_currency := null if {
	currency_authorized
} else := "CURRENCY_MISMATCH"

denial_amount := null if {
	amount_authorized
} else := "AUTHORITY_LIMIT_EXCEEDED"

allow_reasons := [
	"IDENTITY_VERIFIED",
	"TRUSTED_ISSUER",
	"DELEGATION_VALID",
	"WITHIN_SCOPE",
	"WITHIN_AMOUNT_LIMIT",
	"NO_ACTIVE_REVOCATION",
	"REPLAY_SAFE",
]
