# Native OPA tests (Step 8L) — validate policy semantics independently of
# the JS/Wasm runtime. Same canonical scenario as packages/policy tests.
package agenttrust_test

import rego.v1

now := "2026-09-15T12:00:00Z"

base := {
	"actor": {"did": "did:web:agents.acme.example:support-1"},
	"request": {
		"action": "refund:create",
		"resource": "order:ORD-918",
		"audience": "did:web:payments.example:refund-agent",
		"parameters": {"amount": 120, "currency": "SAR"},
	},
	"identity": {"proofVerified": true},
	"credential": {
		"verified": true,
		"issuer": "did:web:acme.example:org",
		"issuerTrusted": true,
		"types": ["VerifiableCredential", "AgentDelegationCredential"],
	},
	"authority": {
		"actions": ["refund:create"],
		"resources": ["order:*"],
		"audience": ["did:web:payments.example:refund-agent"],
		"limits": {"amount": 500, "currency": "SAR"},
	},
	"status": {"credentialActive": true, "quarantined": false},
	"replay": {"checked": true, "claimed": true},
	"context": {"now": now},
}

# `with` cannot appear in a rule head; put it in the function body.
eval(obj) := d if {
	d := data.agenttrust.decision with input as obj
}

# json.patch takes the (target, patches) 2-arg form.
patch(obj, patches) := json.patch(obj, patches)

allow := eval(base)

test_valid_refund_under_limit_allowed if {
	allow.effect == "ALLOW"
	allow.reasonCodes[0] == "IDENTITY_VERIFIED"
}

test_amount_above_limit_denied if {
	result := eval(patch(base, [{"op": "replace", "path": "/request/parameters/amount", "value": 5000}]))
	result.effect == "DENY"
	result.reasonCodes == ["AUTHORITY_LIMIT_EXCEEDED"]
}

test_amount_at_limit_allowed if {
	at := eval(patch(base, [{"op": "replace", "path": "/request/parameters/amount", "value": 500}]))
	at.effect == "ALLOW"
}

test_unauthorized_action_denied if {
	result := eval(patch(base, [{"op": "replace", "path": "/request/action", "value": "payment:create"}]))
	result.effect == "DENY"
	result.reasonCodes == ["ACTION_NOT_IN_SCOPE"]
}

test_unauthorized_resource_denied if {
	result := eval(patch(base, [{"op": "replace", "path": "/request/resource", "value": "tenant:beta"}]))
	result.effect == "DENY"
	result.reasonCodes == ["RESOURCE_NOT_IN_SCOPE"]
}

test_wildcard_resource_prefix_matched if {
	other := eval(patch(base, [{"op": "replace", "path": "/request/resource", "value": "order:ORD-1"}]))
	other.effect == "ALLOW"
}

test_wrong_audience_denied if {
	result := eval(patch(base, [{"op": "replace", "path": "/request/audience", "value": "did:web:evil.example:agent"}]))
	result.effect == "DENY"
	result.reasonCodes == ["AUDIENCE_MISMATCH"]
}

test_wrong_currency_denied if {
	result := eval(patch(base, [{"op": "replace", "path": "/request/parameters/currency", "value": "USD"}]))
	result.effect == "DENY"
	result.reasonCodes == ["CURRENCY_MISMATCH"]
}

test_expired_authority_denied if {
	# "add" creates the key (replace would fail on a missing path).
	result := eval(patch(base, [{"op": "add", "path": "/authority/validUntil", "value": "2026-09-01T00:00:00Z"}]))
	result.effect == "DENY"
	result.reasonCodes == ["AUTHORITY_EXPIRED"]
}

test_not_yet_valid_authority_denied if {
	result := eval(patch(base, [{"op": "add", "path": "/authority/validFrom", "value": "2026-10-01T00:00:00Z"}]))
	result.effect == "DENY"
	result.reasonCodes == ["AUTHORITY_NOT_YET_VALID"]
}

test_missing_required_input_denied if {
	# Without a request, no refund authorization can hold — the policy must
	# DENY deterministically (REQUEST_MALFORMED is the ENGINE's job when the
	# VerifiedFacts schema itself is violated; see packages/policy tests).
	trimmed := object.remove(base, ["request"])
	result := eval(trimmed)
	result.effect == "DENY"
	result.reasonCodes == ["ACTION_NOT_IN_SCOPE"]
}

test_action_missing_from_authority_denied if {
	# The delegation's actions list omits refund:create — even though the
	# request is the supported action, the delegated SCOPE denies it.
	# (Step 13, found by AUTHORITY-002: the original rule checked only the
	# supported-action whitelist, not the delegated action set.)
	result := eval(patch(base, [{"op": "replace", "path": "/authority/actions", "value": ["order:read"]}]))
	result.effect == "DENY"
	result.reasonCodes == ["ACTION_NOT_IN_SCOPE"]
}

test_denial_precedence_action_first if {
	# Action AND amount both violated → action wins (precedence 1 > 7).
	result := eval(patch(base, [
		{"op": "replace", "path": "/request/action", "value": "payment:create"},
		{"op": "replace", "path": "/request/parameters/amount", "value": 99999},
	]))
	result.reasonCodes == ["ACTION_NOT_IN_SCOPE"]
}
