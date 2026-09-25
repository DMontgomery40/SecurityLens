# SecurityLens Afterlife

Research proposal · September 25, 2026 · implementation has not started

## Recommendation

Rebuild SecurityLens around the lifetime of agent-created software and its external effects.

**An agent can finish. What it created must either finish with it or acquire an accountable owner.**

The product makes temporary software practical. An agent can create a service for an afternoon, a data-processing workflow for one task, or a fleet of experiments for a release. SecurityLens records the supported persistent effects as they are created, secures the means to retire them, and resolves their ownership when the task ends. Useful results survive through explicit adoption. Everything else enters a verifiable retirement process.

The ambitious version is a lifecycle layer for a world where software is created for individual tasks. The first version is a small, useful package for agent-generated Cloudflare applications.

“Afterlife” is a working concept name. SecurityLens remains the public brand and domain. This research found a defensible product hypothesis, not proof that nobody has built it. The proposed novelty is the combination of creation-time obligations, independent retirement authority, explicit succession, and observed closure after successful work as well as failure.

## The brief and the current repository

The requested outcome is a substantial reinvention for realistic 2027–2030 agent use. Keeping the current scanner is optional. Agent swarms, APIs, MCP, and generated software should inform the concept; a conventional security dashboard or another model wrapper would miss the brief. No market, budget, or customer segment was prescribed. The initial buyer proposed here is therefore an assumption to validate.

The existing product is an educational vulnerability scanner: React/Vite UI, JavaScript CLI, GitHub crawler, regex pattern library, and Netlify functions. Its README points to securitylens.io. It does not currently implement the lifecycle system described here.

Remote history was fetched on September 25. The remote default is `development` at `ca90d2a`, not the older `main` at `bd57090`. The original checkout also contained the later local scanner fix `4017f90` and 26 uncommitted changed/untracked paths for logging and error handling. A native Codex worktree was created at `/Users/davidmontgomery/.codex/worktrees/securitylens-futures/SecurityLens` on `feat/agent-native-reinvention`. Merge `8bcedb5` contains both remote development and the local fix. All 26 unfinished paths were copied and byte-checked against the original checkout, which was left untouched. Newer Snyk dependency branches exist; they are unmerged proposals, not an integrated product baseline, and were not indiscriminately merged. Dependency modernization remains implementation work.

Research used two independent `gpt-6-astra` agents at high reasoning effort plus lead research. Initial tracks covered agent-native transactions/economics and generated-software verification/composition. Each searched for reasons its preferred ideas already existed. Agreement between agents is a synthesis input, not evidence of novelty or market demand.

## The future assumption that matters

The useful forecast is narrower than “agents replace the web.” It is that creating and activating software becomes much cheaper than maintaining an accurate understanding of everything still running.

Human teams already leave abandoned infrastructure. Agents could change its frequency and granularity: a small task might create several services, schedules, data stores, and downstream agents. A conversation ending does not end those resources. A credential expiring does not cancel previously registered activity. A repository being archived does not stop its deployed copies.

The product is useful if temporary agent-built systems become common. It does not require artificial general intelligence, a fully autonomous economy, or machine-to-machine payments.

| Horizon | Conditional scenario | Product consequence |
| --- | --- | --- |
| 2027 | Builders repeatedly create temporary apps and integrations through agents. | Give each managed application an expiry, an owner, and a reliable close operation. |
| 2029 | Tasks routinely delegate across runners and providers; useful components outlive the initiating task. | Transfer ownership and retirement obligations independently of the original agent. |
| 2030 | Some providers expose lifecycle operations as native capabilities. | Make portable effect records and conformance fixtures interoperable across providers. |

These are design scenarios, not adoption predictions.

## A concrete experience

A user asks an agent: “Build a temporary product-feed comparison service for this launch. Keep the report; shut the experiment down Friday.”

The agent creates a Worker endpoint, a recurring fetch, and a dedicated KV namespace through SecurityLens. Each creation belongs to the task's lifetime. The resulting report is explicitly retained as a deliverable.

On Thursday, another task wants to keep the endpoint. Its accountable owner accepts the service and the associated ongoing obligations. That service survives under the new owner. The remaining temporary resources expire.

Now introduce the hard case: the first agent crashes, its original token is revoked, a provider request times out after succeeding, and a scheduled invocation is already running. The independent lifecycle executor still has its own bounded authority and durable action records. It reconciles ambiguous requests, stops new activity, waits or contains outstanding activity where supported, and verifies retirement. Anything it cannot establish stays unresolved.

The human-facing result is concise:

```text
Launch comparison · finished
Report saved
Comparison service adopted by Catalog Operations
2 temporary resources retired
1 schedule still settling
```

The agent receives the same facts as structured data. It can inspect outstanding obligations, adopt a permitted resource, or continue unrelated work. A red/green security score is unnecessary.

## The product primitive: a consequence lease

This is a proposed application-level contract, not an existing MCP standard. A managed effect is admitted only after its lifecycle record has been durably prepared.

Each record contains:

- The authorizing principal, task, provider account, resource identity, and connector version.
- A lifetime and the event that starts retirement: deadline, completion, cancellation, or abandonment.
- Separate ownership, dependency, and activation relationships. Using an existing shared database does not grant ownership of it.
- A deterministic retirement procedure and its preconditions, plus observations that establish completion for this connector.
- An independent executor identity or capability. Removing the creator's credential must not remove the sole means of retirement.
- A bounded reserve for cleanup attempts, rate-limit headroom, and any explicitly supported cleanup cost. This is operational capacity accounting; financial escrow is not required for the first version.
- The retained-output policy and any later adoption record.
- Residual obligations and unknown outcomes that prevent a clean closure claim.

The key product decision is to secure a feasible ending before allowing a persistent beginning. A cleanup script attached to an agent cannot deliver that after the agent disappears.

Illustrative interface, not implemented commands:

```text
estate.open(owner, expires_at)
effects.create(estate_id, supported_operation, arguments, retirement_policy)
effects.adopt(effect_id, accepting_owner, expected_revision)
estate.close(estate_id)
estate.inspect(estate_id)
```

The `create` wrapper performs the actual supported provider mutation; it is not an agent's optional promise to register a resource later. Prefer provider idempotency keys or deterministic resource names. A lost response must be reconciled against provider state before retrying; uncertain creation remains an obligation.

Adoption requires authorization and acceptance by the new owner. It transfers responsibility for the relevant dependent effects, not just a label on the visible endpoint. It must be atomic with respect to retirement: a late adoption cannot revive an already retired resource or make an old executor delete a newly adopted one. Revision checks and fenced execution are required.

Retirement proceeds from preventing new managed activity to resolving active work, then removing exclusive resources and verifying the resulting state. Deletion acknowledgements and successful HTTP requests are intermediate evidence. Endpoint unreachability is not proof of data erasure. Credential revocation is not proof that already dispatched work stopped.

Closed means every effect within the declared managed scope is either retired to its connector's observed criterion or accepted by a surviving authorized owner. Pending, blocked, unknown, and irreversible consequences remain visible. A close request can be accepted while the estate remains open.

Cycles require ownership analysis rather than naive reference counting. Two abandoned services referencing each other do not become their own justification for perpetual existence. Conversely, a live adopted root must protect its required dependencies. For the first release, arbitrary shared graphs are out of scope: support exclusive resources, explicit adoption of a complete managed application, and references to existing resources that the executor must never delete.

## The evidence behind the opportunity

The [MCP Tasks draft](https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks) explicitly makes cancellation cooperative: an acknowledgement does not require the server to stop. It also permits clients to discard task state after sending cancellation. Its TTL describes task state, not the lifetime of external resources. This establishes a protocol boundary; it does not establish that MCP should itself implement infrastructure cleanup.

Real provider semantics make retirement more than sending DELETE. Cloudflare documents that adding, changing, or deleting [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/) can take up to 15 minutes to propagate. Its [queue purge documentation](https://developers.cloudflare.com/queues/configuration/pause-purge/) states that in-flight messages might still be processed and messages sent during a purge might survive. The queue example informs later scope; Queues are deliberately excluded from the first connector.

Cloudflare already publishes [MCP servers for agent access](https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/). This supports a plausible distribution path through existing agent workflows. It is not evidence that customers want this proposed product.

## Prior art that the concept must beat

These comparisons describe public documentation or advertised behavior inspected during this research. Competitor implementations were not independently executed. Absence of a feature from these pages is not evidence that a vendor cannot implement it.

| Existing work | Already solved or advertised | What SecurityLens would have to add |
| --- | --- | --- |
| [Kubernetes garbage collection](https://kubernetes.io/docs/concepts/architecture/garbage-collection/) and [finalizers](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/) | Ownership relationships, ordered cleanup, delayed deletion. | A convenient agent-task interface for managed external effects, surviving retirement capability, and explicit task-to-task adoption. These are engineering foundations and serious substitutes. |
| [Crossplane managed resources](https://docs.crossplane.io/v2.4/managed-resources/managed-resources/) | Reconciliation of external resources and configurable management/deletion behavior. | Useful task lifetime semantics and demonstrated closure across the supported effects. Building on Crossplane may be better than replacing it. |
| [Port agentic resource management](https://docs.port.io/solutions/agentic-resource-management/overview/) | Agent-accessible provisioning, operation, and decommissioning through governed workflows. | An opinionated, lightweight expiry/adoption contract whose completion survives the creator. This is the strongest commercial adjacency; a generic agent resource portal loses this comparison. |
| [Cloud Custodian](https://cloudcustodian.io/docs/actions.html) and ordinary IaC teardown | Policy-driven cleanup and destruction of declared resources. | Creation-linked effects, positive acceptance of what survives, ambiguous-operation reconciliation, and a completion result agents can use. TTL tags alone are not a differentiator. |
| [Robust Agent Compensation](https://github.com/wso2-incubator/research-rac) | Compensation pairs, transaction records, dependency ordering, and multi-agent rollback. | Independent long-lived obligations after successful temporary work and explicit ownership succession. Compensation itself is prior art. |
| [ChronoMCP](https://chronomcp.dev/) | Impact previews, approval, compensation metadata, and audit trails. | Lifetime and responsibility after a workflow has successfully finished. Do not sell an ordinary undo button as novel. |
| [AgentCore runtime lifecycle settings](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-lifecycle-settings.html) | Runtime session expiry and resource lifecycle controls. | The supported persistent external effects created by the session. Session teardown is a separate boundary. |

The differentiated hypothesis is the complete transaction: creation incurs an independently executable retirement obligation; the obligation outlives its creator; preserving the effect requires an accepted successor; closing the task includes scoped observations of what remains. The individual mechanisms are established distributed-systems techniques.

If Port plus a small lifecycle workflow, or Crossplane plus TTL policy, delivers essentially the same result with less integration burden, use that result to narrow or abandon this product. Novel naming is not a defense.

## Other concepts considered

| Direction | Concrete value | Decision |
| --- | --- | --- |
| Independent evidence for agent-built code | Replace redundant model reviews with a different observable test capable of contradicting the shared assumption. | Strongest alternative. Difficult to generalize without expensive domain-specific oracles. |
| Recall compromised agent knowledge | Trace a bad source into memories, plans, and external actions; quarantine and repair descendants. | Real problem, but direct prior art substantially weakens the novelty claim. |
| Consolidate swarm decisions | One properly scoped human answer resolves several related blockers. | Useful runner feature; uncertain foundation for a separate business. |
| Agent work escrow | Verify delivered work and settle payment. | Too much direct protocol and product overlap to choose as the flagship. |
| Safe tool compiler / action preview | Generate policy-bound preview, commit, and compensation operations from APIs. | Already explicitly proposed in products and repos; reject as the radical new concept. |
| Agent security scanner / registry / trust score | Discover integrations, inspect tools, and classify risk. | Does not meet the requested differentiation. |

The independent-evidence alternative has a real empirical basis: [Correlated Errors in Large Language Models](https://arxiv.org/abs/2506.07962), accepted at ICML 2025, found correlated errors across models in its evaluated tasks. That does not quantify independence in a particular coding pipeline. [Antithesis](https://antithesis.com/docs/introduction/welcome/) already supplies autonomous testing, so SecurityLens would need to prove that repairing shared evidence dependencies adds value beyond existing testing and mutation tools.

[MnemoIR](https://github.com/DheerajPranav/mnemo-ir) already describes compromised-memory tracing, quarantine, repair, and verification. [Agentproof](https://github.com/evanl666/agentproof) explicitly describes API-to-tool generation with preview/commit behavior. These were reasons to move beyond initially attractive ideas.

## The first product worth building

Start with Cloudflare Workers, their Cron Triggers, and dedicated KV namespaces. Support a narrow temporary-application template and complete-application adoption. Provision into a designated development account or scope. The executor must reject targets outside its managed namespace and verified account, including similarly named pre-existing resources.

The package provides an MCP surface, a CLI, a durable lifecycle service, and a small human inspector at securitylens.io. The persistent service runs independently of the creating agent. A local database can support development; a hosted or customer-run deployment needs durable storage, a scheduler, and fenced workers. Stateless request handlers alone cannot fulfill retirement obligations after the client disappears.

The landing experience lets people explore a clearly labeled demonstration of what survives an agent's death, then install the package. The working interface shows current ownership, expiry, retirement progress, retained outputs, and blocked obligations. Controls are “Keep”, “Transfer”, and “Retire”, subject to the underlying authorization policy. Engineering caveats belong in documentation and expandable diagnostics, not unsolicited banners in the main flow.

The initial guarantee is scoped to the managed infrastructure operations. It does not cover arbitrary external effects of uploaded code, resources created with separate credentials, copied data, sent messages, purchases, or a provider's undisclosed replicas. A supported connector must state precisely what it observes. Unknown coverage cannot be silently presented as a clean estate.

Credential separation needs practical validation. Some providers lack delete-only or resource-level credentials. Application-level checks do not transform a broad provider token into a cryptographically restricted capability. Isolate the executor, restrict its account scope, and reject deployment configurations whose trust boundary is unacceptable. Revocation or suspension of the provider account can still make retirement impossible; the obligation remains unresolved.

Default to deterministic lifecycle operations. Models may help a human interpret an unresolved case or propose a connector, but they must not invent a destructive retirement sequence at runtime.

## The demonstration that earns the pitch

Build one normal temporary application, one explicitly adopted application, and one unrelated existing dependency in an isolated test account. Instrument an external observation sink. Then run a failure matrix:

1. Successful task completion retires temporary infrastructure while preserving the retained report.
2. Deadline expiry works while the creator is offline.
3. Kill the creator and revoke its credential; independent retirement still works within its authority.
4. Kill the executor mid-operation; restart converges without duplicate creation or unrelated deletion.
5. Lose a creation response after provider success; reconcile the known operation rather than create an orphan on retry.
6. Race adoption with retirement; exactly one permitted outcome wins, and a stale worker cannot delete the adopted application.
7. Delay or reject provider calls; the estate remains pending or blocked, never falsely closed.
8. Simulate late scheduled activity. Record the last observed activity and the connector's settling criterion; do not promise an instantaneous stop from a config update.
9. Preserve every referenced pre-existing resource. Attempt cross-account and stale-identity targets and verify rejection.
10. Re-run closure; the result is idempotent and preserves previous evidence.

Use deterministic state-machine and fault-injection tests for the lifecycle contract, then perform the actual provider/API and browser checks. The claim is measured managed closure, not universal absence of consequences. Demonstrate the same tasks with a competent baseline using IaC plus TTL cleanup and, where practical, Crossplane or a Port workflow. Count manual interventions and residual effects; do not compare against doing nothing.

Proposed pilot: five design partners and 100 temporary tasks. Record setup time, managed-operation coverage, residual resource-hours after expiry, late external activity, false closure reports, adoption failures, accidental deletion, and manual interventions. Any accidental deletion or false terminal claim blocks expanding scope. Continue only if the supported tasks close with materially fewer interventions or residual effects than the partners' existing lifecycle tools, without custom engineering per task. The pilot and thresholds are proposed acceptance work, not completed results.

Kill or narrow the idea if users cannot route the relevant creations through the boundary, if simple TTL policies already cover their needs, if cleanup credentials require unacceptable privilege, or if the service becomes a connector consultancy. Five partners or 100 tasks would not establish general safety or broad demand.

## Distribution, economics, and the role of the domain

Start with agent app builders, autonomous development platforms, and small teams generating many temporary services. Their immediate purchase is the ability to allow more experiments with less persistent cost and exposure. Developers meet the product in their agent tooling; humans visit the domain to inspect and accept what survives.

Publish the effect-record schema, local executor, and connector conformance fixtures openly. A commercial service can provide durable execution, managed credentials within an explicit trust model, retention, and team adoption workflows. Charge by active managed estates or obligations, with incentives aligned to closing them. Avoid per-alert incentives or charging merely for unresolved obligations created by a service failure.

The possible compounding asset is tested lifecycle behavior: what a provider acknowledges, what actually persists, how retries behave, and how to recover safely. Reusable fixtures can be public or voluntarily contributed. Private code, data, credentials, and estate graphs do not need to become a central training corpus. Whether this advantage survives cloud vendors adding native lifecycle contracts is an open business risk.

The domain becomes the place to answer “what is still alive from this work?” and the machine endpoint for managing those lifetimes. A useful result can move from one agent to another without losing its history or owner. A temporary result can actually end. That is the larger product: make software cheap to create without making abandonment cheap to ignore.

## What to keep from this repository

Keep the domain, repository identity, and any useful UI primitives. Reuse CLI packaging and reporting patterns where they fit the new structured contract. Preserve the unfinished logging work until it is reviewed on its own merits. Use the existing crawler only if a later onboarding step needs repository context.

Retire the educational scanner as the primary experience. Its regex findings cannot establish effect ownership, retirement feasibility, or closure. Preserve the old product through Git history or a clearly separate legacy surface if desired; do not force it into the new trust boundary. Avoid investing in the old firmware roadmap or adding agent branding to the existing severity dashboard.

This is a substantial new backend, not a reskin. The current dependency/runtime baseline also needs a scoped modernization during implementation.

## Research and verification boundary

Completed here: repository/default-branch audit, fresh remote fetch, combined branch with local fixes, byte-preservation of existing edits, primary-source web review, two bounded Astra-high research tracks, and this concrete proposal. External links used in the proposal were opened or returned as primary-source search results. Public product descriptions were treated as claims, not audited implementations.

No product code, provider account, deployment, credential, or live resource was changed for this proposal. No application test/build was run; the owned contribution is a research document. There is no repository documentation check configured. The requested Jev semantic checker was not discoverable in available tools or the inspected project/tool guidance; document consistency was reviewed manually as an explicit fallback. Final document whitespace and original-edit preservation are checked separately.

Next work, if this direction is selected: turn the bounded Cloudflare lifecycle contract and demonstration above into an implementation spec, resolve provider privilege and observable-closure feasibility first, and then build the smallest end-to-end slice. Broad marketplace, reputation, payment, and arbitrary SaaS connectors are outside that first slice.
