# Two-Year Thesis

In two years, agents will routinely act across organizational boundaries —
issuing refunds, negotiating contracts, moving data — and the question "is
this agent allowed to do *this*?" becomes infrastructure, not a product
feature.

Identity alone will not be enough, and this project shows why: a valid
signature proves who holds a key, never whether an action is acceptable.
Authority must be **delegated and attenuated** — scoped to actions,
resources, audiences, amounts, and time — so the blast radius of a
compromised agent is a narrow envelope, not a service account.

Machine-verifiable credentials and status will be the carrier. Revocation an
issuer can publish in minutes — not tickets — becomes the norm, because
agents come and go at a speed human onboarding never matched. The policy
layer stays deterministic and contextual: the same evidence, different
actions, different answers.

Three predictions beyond what this P0 demonstrates. First, trust evidence
becomes **portable**: attestations, status, and history verified against a
DID will be re-verifiable by any counterparty without re-onboarding. Second,
**action provenance becomes contractual** — once agents cause loss, the
hash-chained receipt is the record both sides litigate, so providers who
cannot show "who authorized what, when, against which credential" lose the
deal. Third, agents will need to **refuse unsafe counterparties**: the same
fabric that lets a payer check a payee gives an agent's own operator a
verifiable reason to decline — authority checks cut both ways.

Governance will demand what this system already does: no universal trust
score — scores can't be verified, scoped, or revoked — plus fail-closed
enforcement at every boundary. Interoperable standards (DIDs, VCs, status
lists, policy-as-code) will beat proprietary reputation markets because
they compose across vendors. The trust layer becomes boring plumbing —
which is what infrastructure winning looks like.
