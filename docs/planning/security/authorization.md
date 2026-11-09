# Authorization

## Responsibilities

Authorization decides whether an authenticated or anonymous caller may perform an operation on a protected context.
Butter owns decision contracts and composition while applications own business policy and resource data.

## Authorization manager

An authorization manager evaluates a security context and a typed protected context.
It returns one of:

- `Grant` when its policy explicitly allows the operation.
- `Deny` when its policy explicitly rejects the operation.
- `Abstain` when the policy does not apply.

All-abstain denies by default.
No API should offer a convenient production setting that turns all-abstain into allow.

The manager contract is asynchronous so policies may perform bounded application-owned lookups.
Callers must propagate cancellation and deadlines to those lookups.

## Standard managers

The framework should provide small managers for:

- Permit all.
- Deny all.
- Authenticated caller required.
- Anonymous caller required.
- Exact authority required.
- Any authority required.
- All authorities required.
- Minimum authentication assurance required.
- Conditional delegation.

The framework provides `AllOf`, logical `AnyOf`, `Not` and conditional composition with documented abstain and short-circuit behavior.
Logical `AnyOf` grants when any manager grants, denies when at least one manager denies and none grants, and abstains only when all managers abstain.
Policies that require a veto use the separately named `DenyOverridesAnyOf`, where any denial wins even when another manager grants.

## Request authorization

Request authorization uses normalized method, path, host and selected non-secret request attributes as its protected context.
Matcher selection chooses the policy, and the policy decides access.
The default policy for unmatched requests is deny.

Route-level permit-all still runs the security chain.
It means only that the authorization manager does not require authentication for that route.

## Service authorization

Rust service authorization should use explicit calls rather than reflection or annotation-driven interception.
The same authorization-manager contract can protect a domain operation by receiving a typed resource context.

An application can create a guard that checks developer membership, document ownership or account state before invoking the mutation.
The framework must not infer domain identifiers from arbitrary handler arguments.

Procedural macros for method security are deferred until explicit service guards have demonstrated repetitive boilerplate and stable semantics.

## Authorities and domain policy

Authorities represent coarse application-wide permissions.
They should not encode every resource identifier or tenant membership into the security context.
Large or mutable resource access belongs in application authorization managers that use current domain state.

Role hierarchy is not an initial core feature.
Applications can express hierarchy with composed managers until repeated consumers establish a safe generic model.

## Pre-invocation and post-invocation decisions

The initial framework supports pre-invocation decisions only.
Post-invocation filtering can accidentally expose data before policy is applied and is deferred pending a concrete contract.
Applications must query and construct only data they are authorized to return.

## Denial handling

An unauthenticated caller rejected by an authenticated policy is routed to the configured authentication entry point.
An authenticated caller rejected by policy is routed to the access-denied handler.
Client responses are neutral while internal events carry bounded, non-secret policy identifiers and reason codes.

## Policy observability

Security diagnostics may identify the chain, manager and decision category.
They must not log credentials, full session identifiers, raw tokens or sensitive resource contents.
Authorization success logging is sampled or disabled by default because it can be high volume and privacy-sensitive.
