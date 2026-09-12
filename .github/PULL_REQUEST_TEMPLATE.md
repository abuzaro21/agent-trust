## Summary

<!-- What does this PR change, in one or two sentences? -->

## Scope

<!-- Which components are touched? -->
<!-- apps/ · packages/ · policies/ · tests/ · docs/ · infra/ -->

- [ ] Behavior frozen by an ADR — ADR-____ (if applicable)

## Verification

<!-- Exact commands + results. "Checked and failed" and "could not check" are different — say which. -->

```text

```

## Tests

- [ ] Unit tests added/updated
- [ ] Negative/attack tests added where security semantics changed (deny paths, fail-closed paths)
- [ ] Delegation property tests updated (if `packages/delegation` touched)
- [ ] `opa fmt/check/test` + bundle hash regenerated (if `policies/` touched)

## Security Checklist

- [ ] No permissive fallback introduced on any failure path
- [ ] No key material, secrets, PII, or raw credentials committed
- [ ] Fail-closed behavior documented if a new dependency was added
