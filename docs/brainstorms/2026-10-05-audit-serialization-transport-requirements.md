---
date: 2026-10-05
topic: audit-serialization-transport
issue: https://github.com/praxis-proxy/policy/issues/172
---

# Separate audit serialization from transport, and keep records verifiable off the request path

## Summary

Every audit sink today does two jobs in one `handle` call: it decides what a record looks
like, and it writes the record somewhere. The engine awaits that call before it answers the
request. This spike splits the two jobs. A serializer owns the record's shape, including any
fingerprint, chain link and signature. An exporter owns delivery: stderr, a file, Linux audit,
OTLP later. The engine stamps stream identity before it hands the record off, so a dropped
record leaves a visible gap when a later record arrives. Local exporters land first because
PPE has no buffers, batch exporters or collectors yet. The one rule that
makes tamper-evident records survive this split: nothing downstream of the serializer may
change the bytes a verifier recomputes. The rest of this document is that rule, spelled out as
requirements, plus the delivery guarantees #165 asks for.

## Problem Frame

Three concerns are fused in `AuditHandler::handle` today, and the fusion affects issues #165
and #166.

- **Shape and delivery are one call.** `audit-logger` renders a JSON line and writes it to
  stderr or `tracing` in the same function. `ocsf-audit` (the reference plugin for #12)
  canonicalizes the record, computes its SHA-256 fingerprint, links it to the previous record,
  optionally signs it with ECDSA P-256 under a mutex, and then `eprintln!`s it. The executor
  awaits all of that before returning the verdict. Audit latency is request latency, on L4 and
  L7 alike.
- **No place to put a buffer.** PPE has no exporter abstraction, so "write to OTLP" today would
  mean an HTTP request per verdict inside the handler. The only alternatives are stdout and
  whatever collects it.
- **Loss is silent.** A sink that errors is logged and skipped; a sink that stalls stalls the
  request. Once delivery moves off the request path, a dropped record must become evidence,
  not an absence. The audit seam already stamps `(epoch, stream_id, stream_seq, emission_seq)`
  on each verdict; that is the loss signal, and it only works if the stamp is assigned before
  the record can be lost.
- **Integrity is sink-specific but the pipeline is not.** A chained, signed record is only
  verifiable if the bytes that reach the consumer are the bytes the fingerprint and signature
  cover. A transport layer that re-encodes, reorders fields, batches by wrapping, or
  renumbers will break every record it touches without anyone noticing until verification
  time. The split has to make that impossible by construction, not by convention.
- **Payloads leak by default.** `audit-logger` logs tool and prompt arguments verbatim (#146).
  The OCSF plugin emits content digests. A new engine-built payload view makes argument names
  and types, without values, the default for every sink.

## Actors

- **Operator.** Configures which sinks run, where each one exports, and what guarantee each
  sink gets (inline or queued, and what happens on overflow).
- **Serializer author.** `audit-logger`, `ocsf-audit`, and any third-party sink. Produces
  records from a `DecisionLog`, the payload's audit view and a filtered `Extensions`, and
  from an engine-sanitized effect audit view. Never performs I/O.
- **Exporter.** Built-in delivery: stderr/stdout, file, Linux audit, later OTLP. Writes bytes
  it does not interpret.
- **Engine executor.** Finalizes the verdict, builds each sink's owned audit view, stamps the
  stream fields, hands the record to the sink inline or through a queue, and drains queues on
  shutdown.
- **Downstream consumer.** A log collector, a SIEM, a ledger, or an offline verifier that holds
  nothing but the exported bytes, a public key and the record contract.

## Key Flows

**F1. Inline delivery (today's behavior, kept as the default).** Verdict is finalized; the
executor builds the sink view and stamps the stream fields; the sink serializes and the exporter
writes; the executor returns. Guarantee: the exporter returned before the response was sent.

**F2. Queued delivery.** Verdict is finalized; for each sink the executor builds an owned
payload audit view and filtered `Extensions`, assigns that sink's stream stamp and event time,
and enqueues that view with an owned `DecisionLog` as one ordered step. Effects take the same queue
as owned, engine-sanitized effect audit views derived from `EffectRecord`s. One drain task per
sink dequeues in order, serializes (fingerprint, chain, signature included), batches, and calls
the exporter. Guarantee for an accepted item: it was stamped and enqueued before the response
was sent. A dropped item is stamped and counted, not enqueued; later exported records expose
its missing sequence value.

**F3. Overflow.** The queue in front of the drain task is full. The configured policy decides:
wait for room up to the audit timeout, then drop and count if the wait expires; or drop and
count immediately. The verdict is not changed. Under either drop, the next exported record
exposes any missing `stream_seq` values. Drops at the tail require a
trusted terminal sequence or checkpoint to be visible to an offline consumer. Behind the drain
task, when the exporter cannot keep up, the `spill` policy writes its finished records
to disk in order and the exporter catches up from there; a spilled record is already
serialized, so the disk holds the exact bytes handed to the exporter. Chain links and signatures,
when the serializer supplies them, are already inside those bytes. An unsigned record has no
cryptographic tamper detection in the spill buffer.

**F4. Shutdown, reload and restart.** On shutdown the drain tasks have a bounded deadline to
empty their queues; whatever is left is counted and reported. A reload is a shutdown of the
outgoing executor: `load_config` builds a fresh executor with a new epoch (`engine.rs`), but
reload waits up to the outgoing queue-drain deadline before activating the new executor. Queue
draining adds at most that deadline to reload latency. For each exporter, surviving old-epoch
queue and spill records export before new-epoch records. The new executor may serve requests
while its export waits behind a surviving old spill. There is no ordering promise across
exporters. Undrained records are counted against the old epoch. On restart the epoch changes,
`stream_seq` restarts at 0, and a chained serializer begins a new chain.

**F5. Offline verification.** A consumer takes the exported bytes and the authority's public
key, strips the fields the contract excludes, canonicalizes, recomputes the fingerprint,
checks the signature over the DSSE PAE, walks `prev_event` back along the chain, and reads
`stream_seq` per `(epoch, stream_id)` for one sink's stream. A dense sequence that opens at 0
shows no leading or interior gap in the exported records. It does not prove the tail was
captured: a record lost after the last exported one leaves no gap to see. Tail completeness
needs a trusted terminal sequence or checkpoint from the host, which this document does not
define. A gap, or a head above 0, is reported as evidence of loss (R8), not as a verification
failure: the records on either side of the gap still verify on their own. No PPE code is involved.

## Requirements

**Serializer (the sink owns the shape)**

- R1. A sink implements a serializer that turns a `DecisionLog`, the new engine-built audit
  view of the payload at the verdict (R23), and a filtered `Extensions` into one record:
  owned bytes, a content type, and the stream fields as metadata. Both reference sinks read
  the payload today: `audit-logger` reads tool and prompt fields, and `ocsf-audit` also derives
  `activity_id` and `type_uid`. A sink without the new content capability is handed none.
  The serializer also renders an engine-sanitized effect audit view through a second entry
  point, so the queued path carries effects as well as decisions. It performs no I/O and
  holds no transport.
- R2. Any integrity material a record carries (fingerprint, chain link, signature) is computed
  by the serializer, inside the record, before the record leaves the serializer. Nothing
  downstream computes, recomputes or adds integrity material.
- R3. The bytes a serializer emits are the bytes a verifier recomputes over. No exporter,
  batch, queue or spill may re-encode, reorder, pretty-print, truncate, wrap, or otherwise
  alter them. Framing added for delivery (a newline, a length prefix, an OTLP log body) must be
  removable without ambiguity so the consumer recovers the exact bytes.
- R4. A chained serializer (one whose records reference their predecessor) processes records
  for a given `(epoch, stream_id)` from a single consumer. On the queued path the engine
  stamps and enqueues as one step, so the drain task dequeues in `stream_seq` order and the
  chain order equals the stamp order; a stamp taken on the request task and enqueued later
  would let a drain task see 6 before 5. On the inline path there is no single consumer: the
  chain order is the order records reach the sink's own lock, which can differ from the stamp
  order under concurrent requests. Both orders are inside the bytes, so a consumer follows
  `prev_event` for the chain and `stream_seq` for completeness and never assumes the two
  agree. Concurrency is permitted across sinks and across streams, never within one sink's
  stream.
- R5. Tool and prompt argument values reach a serializer as names and type labels by default,
  with no raw value or value-derived per-argument digest. Other payload bytes are omitted by
  default; structural metadata needed to classify an event remains available. Raw arguments
  require an explicit per-sink opt-in, applied after R22 removes sensitive fields; the docs
  say what that exposes. This closes #146 for every sink. The existing whole-payload
  `input_hash` and `output_hash` remain separate, optional provenance fields. They appear only
  when `capture_content_provenance` is enabled with a named secret or an explicit `unkeyed`
  choice. A missing choice is rejected; the engine never falls back silently to an unkeyed
  digest. The `unkeyed` choice produces `sha256:<hex>` output that
  permits offline guesses of short content; a named secret yields `hmac-sha256:<key_id>:<hex>`.
  The key stays in the engine and never reaches a sink.
- R6. A serializer declares its extension read capabilities as today, and separately declares
  the new content capability from R23. The engine hands it only the filtered `Extensions` and
  payload audit view. The queued path carries the same views as the inline path.

**Engine (stamps before handoff)**

- R7. The executor assigns `epoch`, `emission_seq` and event time to each source event, then a
  sink-qualified `stream_id` and `stream_seq` for each attached sink before handoff in either
  mode. All sink views of one event retain its `emission_seq` and event time. Today
  `emit_decision` calls `stamp_decision_stream` immediately before `emit_audit`; the new per-sink
  stamp and queue start at that handoff, and a decision with no sink attached takes no sequence
  number. Each sink's `stream_seq` is dense within its decision or effect stream. Preserve the
  existing dense source `decision_seq` counter and the monotonic `emission_seq` shared by
  decisions and effects; a per-sink counter must not replace either. Per-sink stamps travel
  with audit items without rewriting the shared `DecisionLog` or durable `EffectRecord`.
  A serializer reads event time from the stamp rather than the clock, so
  a queued record does not claim drain time. `EffectRecord` gains an `event_time` field: the
  engine stamps it after the durable effect-log append and before notifying or enqueuing
  sinks. Nothing later renumbers or restamps.
- R8. `stream_seq` is dense per `(epoch, stream_id)` for each sink stream as emitted by the
  executor. A gap in an exported stream means a record existed and was lost after stamping;
  the exporter and consumer treat it as evidence, never as something to repair or skip over.
- R9. Route-resolution denials and assertion denials are stamped and delivered like any other
  verdict (#84 already does this inline; the queued path keeps it).

**Exporter (transport owns delivery)**

- R10. An exporter trait accepts a batch of serialized records and delivers them. Batch
  boundaries carry no meaning; a consumer must not be able to tell where one batch ended.
  A retry sends the same bytes and record identity, so a consumer can deduplicate it (R24).
- R11. Exporters are configured on the sink's `plugins:` entry, not implemented by the sink.
  One serializer produces a record once, then fans out its byte-identical result to each
  configured exporter. Separately configured sink instances have distinct stream identities
  under R24.
- R12. The first exporters are local: stderr and stdout (one record per line), file
  (append-only, one record per line, with an fsync policy the operator chooses), `tracing`
  (one event per record at a fixed target, the record as a single field holding the exact
  bytes, so today's `destination: tracing` configurations map onto it; the host's subscriber
  owns the framing around that field, so R3 holds only as far as the subscriber emits the
  field verbatim or as an unambiguously escaped string, which the docs say), and Linux audit
  as an optional, feature-gated exporter. Every exporter's blocking I/O, a stderr or stdout
  write included, runs off the async runtime in both delivery modes: a write to a full pipe
  blocks inside `poll` where the audit timeout cannot cut it off, so a stalled reader would
  otherwise park a runtime worker (the blocking `eprintln!` #165 calls out). OTLP follows once
  the local exporters are in.
- R13. An exporter that needs network transport receives it from the engine as a long-lived
  service with its own grant, per the rule #164 settles. It never copies a request's transport
  slot.
- R14. Each exporter reports records written, bytes written, write errors and write latency.
  Each sink reports queue depth, records dropped by policy, and records left undelivered at
  shutdown. It also reports queue-wait expirations and drain-task failures or restarts.

**Delivery guarantee (what #165 asks for)**

- R15. Delivery is configured per sink as `inline` (default) or `queued`. The docs name the
  guarantee of each in one sentence apiece (F1 and F2 above), with the queued guarantee
  applying only to an accepted enqueue.
- R16. A queued sink has a queue bounded by item count and retained bytes in front of its drain
  task. Two overflow policies apply: `block` waits at most
  `engine_settings.audit_timeout_milliseconds` for room,
  then drops and counts the stamped record without changing the verdict; `drop-counted`
  drops and counts immediately. A later exported record exposes a missing `stream_seq` value;
  a tail drop needs the local counter or a trusted checkpoint.
  Behind the drain task, `spill` is the exporter-stage policy: when the exporter falls behind,
  the drain task's finished records go to an on-disk buffer in dequeue order, preserving
  `stream_seq` within each stream, and the exporter drains them later. Spill holds serialized
  records, never `DecisionLog`s: a record spilled before serialization would be chained by
  a restarted serializer with no chain state, opening a second chain for the old epoch.
  Anyone who can write the spill directory would get their edits signed on the way out when
  signing is enabled. Spill preserves the serializer's integrity material but does not make
  an unsigned record tamper-evident. The policies are
  explicit in config; there is no silent default beyond `inline`. Queue occupancy is depth
  times retained view size, which can exceed serialized record size; the byte bound prevents
  one large view from defeating the memory limit.
- R17. Shutdown drains every queue with a bounded deadline and reports what did not drain. A
  reload waits up to that deadline for the outgoing executor (F4). For a shared exporter,
  old-epoch queue and spill records precede new-epoch exports; independent exporters have
  no cross-exporter order. A spilled buffer survives a restart with finished bytes and needs
  no chain state to resume.
- R18. Before the queued path is implemented, `ppe-benches` records inline per-record engine
  cost for each sink. Afterward it measures queued request latency, per-sink view cloning
  cost, retained queue bytes at configured depth, and signed serializer throughput under one
  drain task, so the gain and the new request-path cost are both measured.

**Verification contract**

- R19. A signed `ocsf-audit` record is verifiable offline from its exact exported bytes,
  the authority's public key and AID-EMIT-1 (sections 4, 6, 7 and 11). For `tracing`, this
  guarantee applies only to documented subscriber configurations that preserve the record
  field verbatim or escape it reversibly; other subscribers cannot promise byte recovery.
  The standalone validator is published in Levaj2000/AI-Identity (R19 does not require PPE
  code on the verifier's machine).
- R20. Operator-authored persisted configuration names signing keys through the secrets
  registry (`SecretProvider`, #92), never as literal private keys. In-memory
  `signing_key_pem` injection for tests, demos or a trusted secret manager remains allowed;
  the plugin clears both configuration copies after construction. The record carries the
  `kid` that selects the authority's published public key, not a key-set URL.

**Docs**

- R21. The auditing guide documents the serializer and exporter split, the two delivery modes
  and their guarantees, the two queue policies and the spill policy and what each does to the
  stream, the argument-name-and-type default and raw-value opt-in, the separate optional
  whole-payload digests, and how a consumer verifies a record offline.

**Sensitive data (the engine removes, the sink renders)**

- R22. Sensitive data is removed by the engine before a record is handed to any sink, never by
  a sink or an exporter. This is a sink-only stage after the shared `filter_extensions`:
  ordinary plugins retain the headers they are granted, while sink views drop transport
  secrets (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API-key headers,
  and an operator-supplied list). `SecretHeaderProvenance` is the existing precedent for a
  marker that contains no secret value. The sink-only stage also handles open-ended slots (`cmf.mcp`
  annotations and schemas, violation details), where it drops a value or replaces it with a
  keyed digest rather than masking it, since a mask destroys evidence and is still a value a
  sink might hash. For tool and prompt arguments the rule is by name: an argument whose name
  matches a mandatory default set (`password`, `passwd`, `secret`, `token`, `api_key`,
  `authorization`, `credential`, compared case-insensitively, at any depth of the argument
  object) or a name or JSON path on the operator-supplied list is removed. Operators may add
  names and paths but cannot subtract from the default set. A value-level rule that looks at
  content rather than names is not promised here. Removal happens before the
  record exists, so it is inside the hashed bytes and a verifier recomputes what was exported.
  The engine adds removed header names and argument or field paths (and optionally a count),
  never their values, to the sink view. The serializer renders that marker inside the record,
  so a consumer can tell redacted from never present. A sink decides only how to render what it
  was given, argument names and types by default (R5); the per-sink raw-argument opt-in renders
  what survived removal and cannot restore what the engine removed. The same rule covers effects:
  after the write-ahead append, the engine builds a separate sink view of `EffectRecord` without
  changing the durable record used for reconciliation. Open-ended `details` values are dropped
  or keyed-digested. Arbitrary `description` and `key` strings are keyed-digested under a
  configured secret or omitted when no secret is configured. `kind` is a non-sensitive
  classification identifier that plugin authors must not fill with request data. A sink
  never receives the raw effect values.

**Audit views, identity and failures**

- R23. The engine adds an owned payload audit view for each sink before inline handoff or
  enqueue. Today `AttachedSink::view` filters only `Extensions` and `emit_audit` passes the
  original payload to every sink; no content capability exists. The new content capability
  selects the fields a sink may read, while R5 and R22 determine the values in its view.
  A sink without that capability receives no payload content. The queue retains only this
  owned view, never an unrestricted `PluginPayload` reference. The shape and copy cost are
  settled in planning and measured under R18.
- R24. Sink identity belongs in the record's existing `stream_id`, not only in an exporter
  destination. The sink instance and record kind qualify that ID: each decision or effect
  stream has a dense counter, including when a sink is attached or replaced mid-run. One
  serializer invocation may fan out the same serialized record to several exporters; retry
  and fan-out preserve its bytes,
  stamp and record UID. A consumer deduplicates those copies by `metadata.uid` for
  `ocsf-audit`, or by `(epoch, stream_id, stream_seq)` for `audit-logger`, before checking
  gaps. Records from distinct sink instances are not duplicates.
- R25. The drain task contains each serializer or exporter panic and bounds each call.
  Its supervisor runs on the request-serving runtime, restarts a failed task and reports the
  failure, stamped records left undelivered, and any export whose outcome is uncertain under
  R14. A retry sends the same finished bytes and identity under R24. If serializer chain
  state cannot be recovered confidently, the old stream stops, pending records are counted,
  and a new sink stream starts at `stream_seq` 0; a second chain never opens under the old
  `stream_id`.

## Acceptance Examples

- AE1. **Covers R3, R11, R24.** Given one `ocsf-audit` serializer fanning out to stderr and
  file, when the committed conformance vectors are replayed, the records recovered from
  both destinations have the same bytes and `metadata.uid` as each other and the updated
  vectors. A collector treats the two copies as one event.
- AE2. **Covers R2, R4, R7.** Given `ocsf-audit` in `queued` delivery with the `block`
  policy and a queue sized for the run, when 10,000 verdicts are driven from 8 connections,
  the exported stream has `stream_seq` 0 through 9,999 with no gap, the chain order equals the
  `stream_seq` order, every `prev_event` matches its predecessor's recomputed fingerprint,
  every signature verifies offline, and every record's event time lies between the request's
  arrival and the verdict rather than at drain time.
- AE3. **Covers R8, R16.** Given a queue of depth 64 and the `drop-counted` policy, when the
  exporter is stalled for the duration of 200 verdicts, then resumes and exports a later
  verdict without another drop or write error, the sink's drop counter equals the number of
  missing `stream_seq` values before that later verdict, and the records on either side of each
  gap still verify.
- AE4. **Covers R9.** Given a route that does not resolve and a sink in `queued` delivery, the
  denial is stamped, delivered, and verifies like an allowed verdict.
- AE5. **Covers R17.** Given a `spill` policy and 500 serialized records in the spill buffer
  at shutdown, when the engine restarts, the 500 records are exported byte-identical under the
  old epoch before the first record of the new epoch, every one still verifies, and the new
  epoch opens at `stream_seq` 0. Given a reload instead, the call waits no longer than its
  outgoing queue-drain deadline, reports undelivered records, and each shared exporter
  sends old-epoch records before new-epoch records.
- AE6. **Covers R5.** Given `audit-logger` with default settings and a tool call whose
  arguments contain a value the engine does not remove (an employee id, say), the exported
  record carries the argument's key and type, with no raw value or value-derived argument
  digest. With the opt-in set, it carries the value, and the docs say so. A value the engine
  removes stays absent: no opt-in brings it back. With content provenance off, whole-payload
  hashes are absent; an explicitly unkeyed provenance hash is documented as guessable.
- AE7. **Covers R6, R23.** Given a sink with neither `read_agent` nor the new content
  capability, its inline and queued records contain neither agent fields nor payload
  content; a sink with the content capability receives only its engine-built audit view.
- AE8. **Covers R18.** The benchmark from R18 reports per-record engine cost for
  `audit-logger` and `ocsf-audit` (chained, signed) under inline delivery, and the same under
  queued delivery after the change, including per-sink view-copy cost and retained queue
  bytes at depth, with signature cost shown to have left the request path.
- AE9. **Covers R19, R20.** Given the file exporter's output and the operator's published
  key set, a verifier resolves the record's `kid` against that set and reports fingerprint,
  signature, chain and stream checks as passing, with no PPE code on the machine.
- AE10. **Covers R5, R22.** An attempt to remove `api_key` from the mandatory set is rejected.
  With valid configuration, given a request carrying an `Authorization` header and a tool call
  whose arguments include `api_key`, with `audit-logger` and `ocsf-audit` both attached and
  both set to the raw-argument opt-in, neither exported record contains the header or
  `api_key` value. Both carry a removal marker naming the header and argument, and the
  `ocsf-audit` record still verifies offline.
- AE11. **Covers R22.** Given an `EffectRecord` whose `description`, `key` and `details` contain
  sensitive values, with a provenance key configured, both sinks receive only the
  sanitized effect view and export none of those raw values. The exported record names the
  removed fields, while the write-ahead effect log retains the original record and key for
  reconciliation.
- AE12. **Covers R12.** Given a stalled stderr reader, unrelated requests continue on the
  async runtime while the exporter's blocking write waits off-runtime in both delivery modes.
- AE13. **Covers R14, R17.** Given a failing exporter and a shutdown deadline, metrics
  report write errors, latency, queue depth, policy drops and records left undelivered under
  the outgoing epoch.
- AE14. **Covers R24, R25.** Given an exporter retry and two independent sink instances,
  retried bytes keep their record UID, while the two sinks use distinct stream ids. Given a
  serializer panic, the drain task contains it, reports loss and restarts; if chain state is
  uncertain, the next record opens a new stream at 0 and no second chain opens in the old one.
- AE15. **Covers R16.** Given a full queue under `block`, the wait ends by
  `audit_timeout_milliseconds`; the stamped item is dropped and counted, and the verdict is
  unchanged.

## Success Criteria

- `audit-logger` and `ocsf-audit` both run as serializers behind the same exporter trait.
  For inputs unaffected by R5 and R22, and with a fixed event time, existing field names,
  encoding and integrity contracts are preserved. The intentional R5, R7 and R22 changes have
  updated fixtures and a documented migration note.
- The queued path exists, is off by default, and every one of AE1 through AE15 is a named
  test or benchmark in the tree.
- A consumer holding bytes from a built-in exporter can verify a signed `ocsf-audit` record
  offline without PPE source; `tracing` requires a subscriber that preserves or reversibly
  escapes the record field.
- A planner can sequence the exporter trait, the local exporters, the queue, and the
  benchmark without inventing an ordering rule, an overflow semantic, or a framing format.

## Scope Boundaries

- No anchoring, checkpoints, witnesses, transparency logs or ledgers. Those are consumers of
  the exported stream, not part of PPE. The ledger demo stays in the demos repository.
- No OTLP exporter in the first increment; its framing is an outstanding question below.
- No key rotation or key management policy beyond resolving a key by reference.
- No change to AID-EMIT-1's verification algorithms or OCSF field types; this document
  consumes the contract while changing some field values and adding removal metadata.
- No change to what the audit seam observes or to ordinary plugins' extension filtering.
  The sink-only payload view, redaction stage and event time change what sinks receive,
  without changing what the policy pipeline observes.

## Key Decisions

- **The serializer computes integrity, not the exporter.** Exporters are meant to be swapped
  freely and to know nothing about the record. If integrity lived in transport, every exporter
  would be a verification dependency and a swap could silently change what a signature
  covers.
- **The engine stamps, not the sink.** A record dropped under queue pressure never reaches the
  sink. If the sink assigned `stream_seq`, the exported stream would be dense by construction
  and the loss invisible. Stamping before handoff is what makes the gap the evidence.
- **One drain task per sink, in stream order.** A chain is a linked list; its links must be
  built in order by one writer, and the writer sees records in stamp order only if the stamp
  and the enqueue are one step. Parallelism is available across sinks and streams, which is
  where the fan-out is anyway.
- **Spill after serialization, not before.** The bytes on disk are the bytes a verifier
  receives, and signed records retain their tamper evidence without chain state after a
  restart. Unsigned records do not gain tamper evidence from spill. The cost is that spill
  cannot relieve a drain task that is itself the bottleneck; that case is `block` or
  `drop-counted`, in the open.
- **Local exporters first.** PPE has no collector stack to lean on, and the operators Teryl and
  Fred asked inside Red Hat all run one already. Local output into an existing collector is
  the shortest path to production and adds no network dependency to the data plane.
- **Batches carry no semantics.** The moment a batch boundary means something, a consumer has
  to reconstruct it, and a transport retry can change it. Records are the unit; batches are a
  transport optimization only.
- **Argument names and types by default, for every sink.** The engine builds this view
  before any serializer sees the payload. Optional whole-payload provenance digests remain
  separate; an unkeyed digest requires an explicit operator choice.
- **The engine redacts, the sink renders.** If each sink redacted for itself, the weakest sink
  would set the exposure and every new sink would reinvent the list. Done once in the engine,
  in a sink-only view after ordinary extension filtering, the rule is uniform across sinks
  without removing headers from identity plugins. It sits inside the hashed bytes, so
  verification is unaffected.
- **Record identity follows the sink, then the exporter fans out.** Independent sink
  instances have distinct streams. Copies and retries of one serialized record retain its
  UID and stamp so a collector can deduplicate them without hiding sequence loss.

## Dependencies / Assumptions

- #84 is merged and `emit_decision` is the single place a verdict is finalized and stamped.
- #12 tracks the `ocsf-audit` serializer being ported under `reference/plugins/` in #171;
  this document assumes it is the first sink with integrity requirements.
- #164 settles how a background drain task obtains an engine-tracked runtime and how an
  exporter holds a transport grant; R13 and R17 depend on its answer.
- #35 has merged `ppe-benches`, the home for R18's benchmark.
- #106 and #107 (serialize the decision log; record plugin id, kind and duration on a step)
  change what a serializer has available but not the split described here.
- The record contract for `ocsf-audit` is AID-EMIT-1 1.2.0-draft at `abc7bd8` in
  Levaj2000/AI-Identity (`docs/specs/aid-emit-1.md`), using `aid.*` keys. Its standalone
  validator is `scripts/aid_emit1_validator.py` in that repository; Praxis may vendor or
  link it.

## Outstanding Questions

### Deferred to Planning

- [Affects R1, R10][Technical] Exact trait shapes for serializer and exporter, and whether a
  serialized record is `Bytes` plus metadata or a small struct the exporter can inspect for
  routing without reading the body. Consider a mutable serializer interface so one consumer
  owns chain state rather than relying on an internal mutex.
- [Affects R3][Needs research] OTLP framing that satisfies R3: the record as an opaque log
  body with stream fields as attributes keeps the bytes intact; mapping fields into
  structured attributes re-encodes them and breaks verification. Confirm the collector side
  can recover the body byte-for-byte.
- [Affects R4, R24][Technical] Whether a chained serializer is one instance per sink stream or
  one instance guarding several streams, and how stamp and enqueue become one step: a lock
  around counter allocation plus push, or a sequence-ordered channel. `emit_decision` already
  calls `stamp_decision_stream` immediately before `emit_audit`; the queue starts there.
- [Affects R12][Technical] File exporter rotation, fsync cadence, and whether rotation is PPE's
  job or the collector's. Linux audit record format and size limits.
- [Affects R16, R17][Technical] Spill buffer format and location (the records are already
  framed per R3, so the buffer is the exporter's framing on disk), and how the spilled epoch is
  read back so the old epoch drains ahead of the new one on restart.
- [Affects R5, R23][Technical] The exact owned payload-view type, its names-and-types
  representation, metadata needed by OCSF, and the request-path copy cost per queued sink.
- [Affects R18][Technical] Benchmark harness inside `ppe-benches`: what per-record engine
  cost measures, including view copies and queue memory, and whether the existing
  `panic_drive` style of driving a real engine through `load_config` is the right vehicle.
- [Affects R20][Technical] Whether the reference plugin resolves its signing key through
  `SecretProvider` directly or through a host-provided key handle, and how the key identifier
  in the record maps to a provider reference.
- [Affects R22][Technical] The operator-facing shape of the additive removal list (how the
  mandatory default set and the operator's names and JSON paths are configured), where the
  removal marker lives (a typed slot or `unmapped`), how
  effect fields are represented in the sanitized sink view, and whether a value-level rule
  is ever added for open-ended slots; R22 promises only the by-name rule.
- [Affects R24][Technical] How sink identity is encoded in `stream_id`, how counters restart
  when a sink is attached or replaced, and how the serializer's UID maps to that identity.
- [Affects R25][Technical] Supervisor and retry mechanics, including how a partially written
  export is reported and when chain state is known to be safe to reuse.
