# Butter Actuator endpoint and web exposure

## Endpoint model

An Actuator endpoint has a validated stable identity, operation metadata and a typed operation implementation.
The first endpoint identity is `health`, and its first operation kind is read.
Endpoint construction and discovery are explicit and local to one Actuator instance.

The initial typed health operation accepts one of three built-in views:

- Overall health.
- Liveness.
- Readiness.

The operation returns a transport-independent result containing a sanitized aggregate status.
Contributor errors, HTTP status codes, paths, headers and serialized bytes are not part of that result.

The operation catalog exists to keep endpoint definition separate from transport mapping.
It does not require the first slice to expose arbitrary user-defined operations, write operations or untyped payload values.
Any future generic registration API must preserve typed construction, deterministic discovery and safe diagnostics before it becomes public.

## Initial HTTP routes

When an Actuator is attached to Boot, the adapter exposes exactly these routes on the main application listener:

| Method | Path | View |
| --- | --- | --- |
| `GET`, `HEAD` | `/actuator/health` | Overall health |
| `GET`, `HEAD` | `/actuator/health/liveness` | Liveness |
| `GET`, `HEAD` | `/actuator/health/readiness` | Readiness |

The initial slice does not support a configurable base path, path aliases or a second management port.
`HEAD` evaluates the same in-memory operation and returns the same status and headers as `GET` with no response body.
Requests using methods other than `GET` and `HEAD` receive the ordinary method-not-allowed response from the HTTP stack.
Query parameters do not enable details or trigger a probe.

## Response contract

A healthy result uses status code 200 and a JSON body equivalent to:

```json
{"status":"UP"}
```

An unhealthy result uses status code 503 and a JSON body equivalent to:

```json
{"status":"DOWN"}
```

Responses identify the JSON content type and send `Cache-Control: no-store`.
The initial public body contains no contributor names, error messages, timestamps, durations, host details or configuration values.
Serialization failure is treated as an internal adapter defect and must not fall back to formatting a retained contributor error.

The 200 and 503 mapping belongs to Boot's HTTP adapter.
A non-web caller observes the typed aggregate status directly.

## Protected route ownership

Actuator routes are assembled outside ordinary application admission so readiness can be observed while application traffic is refused.
Their handlers remain bounded, synchronous state reads and do not bypass listener or supervisor ownership.

When an Actuator is attached, Boot reserves the `/actuator` route subtree for management composition.
An application route, nested router or wildcard that can claim any reserved path causes assembly to fail before listener binding.
The adapter must use `butter-web` route inventory and conflict checks rather than inspect raw Axum internals independently.

When no Actuator is attached, Boot exposes no Actuator routes and does not reserve the subtree.
Compiling Actuator support without calling `Application::actuator` has no HTTP effect.

## Legacy probe transition

The framework-provided `/live` and `/ready` routes are removed in the same implementation slice that adds the Actuator routes.
They are not retained as aliases, redirects or compatibility handlers.
A default application therefore receives 404 for both legacy paths after the transition.

The legacy paths are no longer reserved after removal.
An application can claim one as an ordinary application route, but Butter does not treat that route as a health probe.
Operators and examples must migrate to `/actuator/health/liveness` and `/actuator/health/readiness` in the same downstream revision update.

## Security boundary

The initial endpoint bodies are deliberately minimal so orchestrators can use them without application credentials.
They still expose process availability and must be deployed according to the consuming application's network policy.
Actuator does not install authentication, trust forwarding headers or infer a private network.

Future endpoints that expose details or perform mutation require a separate exposure and authorization design.
They must not inherit public reachability merely because the health endpoint is public.

## Availability limitations

Serving health on the main listener proves that the application's actual HTTP connector can accept and answer a small request at that instant.
It does not prove that an immediately following request will be admitted or completed.
A closed listener makes every HTTP health route unreachable regardless of the last in-process status.
During startup the routes do not exist before listener binding, and during completed shutdown they cannot report a final state.
