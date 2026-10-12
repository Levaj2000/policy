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
OTLP later. The engine stamps stream identity before it hands the record off, so a record that
is dropped between stamp and export leaves a visible gap rather than silence. Local exporters
land first because PPE has no buffers, batch exporters or collectors yet. The one rule that
makes tamper-evident records survive this split: nothing downstream of the serializer may
change the bytes a verifier recomputes. The rest of this document is that rule, spelled out as
requirements, plus the delivery guarantees #165 asks for.

## Problem Frame

Three concerns are fused in `AuditHandler::handle` today, and the fusion is what #165 and
#166 both run into.

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
  The OCSF plugin emits digests. A serializer boundary is the place to make digest-only the
  default for every sink.

## Actors

- **Operator.** Configures which sinks run, where each one exports, and what guarantee each
  sink gets (inline or queued, and what happens on overflow).
- **Serializer author.** `audit-logger`, `ocsf-audit`, and any third-party sink. Produces
  records from a `DecisionLog`, the payload's audit view and a filtered `Extensions`, and
  from an `EffectRecord`. Never performs I/O.
- **Exporter.** Built-in delivery: stderr/stdout, file, Linux audit, later OTLP. Writes bytes
  it does not interpret.
- **Engine executor.** Finalizes the verdict, stamps the stream fields, hands the record to the
  sink inline or through a queue, and drains queues on shutdown.
- **Downstream consumer.** A log collector, a SIEM, a ledger, or an offline verifier that holds
  nothing but the exported bytes, a public key and the record contract.

## Key Flows

**F1. Inline delivery (today's behavior, kept as the default).** Verdict is finalized; the
executor stamps the stream fields; the sink serializes and the exporter writes; the executor
returns. Guarantee: the exporter returned before the response was sent.

**F2. Queued delivery.** Verdict is finalized; the executor stamps the stream fields and the
event time and, in the same step, enqueues an owned `DecisionLog`, an owned copy of the
payload's audit view for a sink that reads content, and the sink-filtered `Extensions`; the
executor returns. Effects take the same queue as `EffectRecord`s. One drain task per sink
dequeues in order, serializes (fingerprint, chain, signature included), batches, and calls the
exporter. Guarantee: the record was stamped and enqueued before the response was sent, and
records leave the queue in the order they were stamped.

**F3. Overflow.** The queue in front of the drain task is full. The configured policy decides:
block the request until there is room, or drop the record and count it. Under drop, the
exported stream shows a `stream_seq` gap exactly where the record was. Behind the drain task,
when the exporter cannot keep up, the `spill` policy writes the drain task's finished records
to disk in order and the exporter catches up from there; a spilled record is already
serialized, chained and signed, so the disk holds nothing that can still be altered unnoticed.

**F4. Shutdown, reload and restart.** On shutdown the drain tasks are given a bounded deadline
to empty their queues; whatever is left is counted and reported. A reload is a shutdown of the
outgoing executor: `load_config` builds a fresh executor with its counters at zero and a new
epoch (`engine.rs`), so the outgoing executor's queues drain under its own epoch, with the same
deadline, before the new executor exports its first record, and what did not drain is counted
against the old epoch rather than silently dropped at its tail. On restart the epoch changes,
`stream_seq` restarts at 0, and a chained serializer begins a new chain. A consumer sees a new
epoch, not a gap.

**F5. Offline verification.** A consumer takes the exported bytes and the authority's public
key, strips the fields the contract excludes, canonicalizes, recomputes the fingerprint,
checks the signature over the DSSE PAE, walks `prev_event` back along the chain, and reads
`stream_seq` per `(epoch, stream_id)`. A dense sequence that opens at 0 shows no leading or
interior gap in the exported records. It does not prove the tail was captured: a record lost
after the last exported one leaves no gap to see, so completeness at the tail needs a trusted
terminal sequence or checkpoint from the host, which this document does not define. A gap, or
a head above 0, is reported as evidence of loss (R8), not as a verification failure: the
records on either side of the gap still verify on their own. No PPE code is involved.

## Requirements

**Serializer (the sink owns the shape)**

- R1. A sink implements a serializer that turns a `DecisionLog`, the payload as it stood at
  the verdict, and a filtered `Extensions` into one record: owned bytes, a content type, and
  the stream fields as metadata. Both reference sinks read the payload today (`audit-logger`
  for tool and prompt fields, `ocsf-audit` for `activity_id` and `type_uid` as well), and a
  sink that declares no content capability is handed none. The same serializer renders an
  `EffectRecord` through a second entry point, so the queued path carries effects as well as
  decisions. The serializer performs no I/O and holds no transport.
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
- R5. Payload content reaches a serializer as digests by default. The engine digests tool
  and prompt arguments before handoff, the way it already takes `input_hash` and
  `output_hash` in the executor so that no sink holds the provenance key; a serializer renders
  the digests it is given and never keys one itself. Raw arguments appear only under an
  explicit per-sink opt-in that the engine honors when it builds that sink's view, in the
  same way it honors the read capabilities, and the docs say what that exposes. This closes
  #146 for every sink, not only `audit-logger`. A digest of a low-entropy value (an account
  number, a short prompt) is guessable by anyone holding the exported record, so the digest is
  keyed where the host provides a key (`engine_settings.content_provenance_key`, #84, rendered
  as `hmac-sha256:<key_id>:<hex>`), the key never travels with the record or reaches a sink,
  and the unkeyed `sha256:<hex>` form is documented as guessable rather than presented as
  redaction.
- R6. A serializer declares the content it reads (the existing sink capabilities), and the
  engine hands it a filtered `Extensions` with nothing else. The queued path carries the same
  filtered view as the inline path.

**Engine (stamps before handoff)**

- R7. The executor assigns `epoch`, `stream_id`, `stream_seq`, `emission_seq` and the event
  time when the verdict is finalized, before the record is handed to any sink, inline or
  queued. The stamps ride inside the serialized bytes, and a serializer takes the event time
  from its stamp rather than reading the clock: both reference sinks read the clock when they
  build a record today, and `DecisionLog` carries no time, so a queued record would otherwise
  claim drain time and a spilled one a post-restart time, inside the signed bytes. Effects
  carry their time on the `EffectRecord` the same way. Nothing later renumbers or restamps.
- R8. `stream_seq` is dense per `(epoch, stream_id)` as emitted by the executor. A gap in an
  exported stream therefore means a record existed and was lost after stamping; the exporter
  and the consumer treat it as evidence, never as something to repair or skip over.
- R9. Route-resolution denials and assertion denials are stamped and delivered like any other
  verdict (#84 already does this inline; the queued path keeps it).

**Exporter (transport owns delivery)**

- R10. An exporter trait accepts a batch of serialized records and delivers them. Batch
  boundaries carry no meaning; a consumer must not be able to tell where one batch ended.
- R11. Exporters are configured on the sink's `plugins:` entry, not implemented by the sink.
  The same serializer wired to two different exporters produces byte-identical records.
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
  shutdown.

**Delivery guarantee (what #165 asks for)**

- R15. Delivery is configured per sink as `inline` (default) or `queued`. The docs name the
  guarantee of each in one sentence apiece (F1 and F2 above).
- R16. A queued sink has a bounded queue in front of its drain task with one of two overflow
  policies: `block` (the request waits, latency returns under load) or `drop-counted` (the
  record is dropped, the drop is counted per sink, the stream shows the gap). Behind the drain
  task, `spill` is the exporter-stage policy: when the exporter falls behind, the drain task's
  finished records go to an on-disk buffer in `stream_seq` order and the exporter drains them
  later. Spill holds serialized records, never `DecisionLog`s: a record spilled before
  serialization would be chained by a restarted serializer with no chain state, opening a
  second chain for the old epoch, and anyone who can write the spill directory would get their
  edits signed on the way out. The policies are explicit in config; there is no silent default
  beyond `inline`.
- R17. Shutdown drains every queue with a bounded deadline and reports what did not drain. A
  reload is a shutdown for the outgoing executor (F4): its queues drain under its epoch before
  the new executor exports. A spilled buffer that survives a restart holds finished records
  whose epoch is inside their bytes, and is exported under that epoch before the new epoch
  begins exporting, so the two never interleave on the same exporter and no chain state is
  needed to resume it.
- R18. Before the queued path is implemented, a benchmark records the per-record engine cost
  of each sink under inline delivery, so the gain is measured rather than assumed.

**Verification contract**

- R19. A record exported by any built-in exporter is verifiable with nothing but its bytes,
  the authority's public key and the record contract. For `ocsf-audit` that contract is
  AID-EMIT-1 (sections 4, 6, 7 and 11: covered bytes, chain fields, stream stamps, and the
  verification procedure) and the standalone validator that ships with it. No PPE binary or
  source is needed to verify.
- R20. Signing keys are resolved through the secrets registry (`SecretProvider`, #92) by key
  reference. A key never appears as a literal in a sink's configuration, and the key identifier
  that resolves the public key rides in the record.

**Docs**

- R21. The auditing guide documents the serializer and exporter split, the two delivery modes
  and their guarantees, the three overflow policies and what each does to the stream, the
  digest-only default and its opt-in, and how a consumer verifies a record offline.

**Sensitive data (the engine removes, the sink renders)**

- R22. Sensitive data is removed by the engine before a record is handed to any sink, never by
  a sink or an exporter. The engine drops from every sink's view the transport secrets no sink
  should see (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API-key headers,
  and an operator-supplied list), and applies the same rule to the open-ended slots (`cmf.mcp`
  annotations and schemas, violation details), where it drops a value or replaces it with a
  keyed digest rather than masking it, since a mask destroys evidence and is still a value a
  sink might hash. Removal happens before the record exists, so it is inside the hashed bytes
  and a verifier recomputes what was exported. The engine marks what it removed, inside the
  record (the dropped names, or a count), so a consumer can tell redacted from never present.
  A sink decides only how to render what it was given, digests by default (R5); the per-sink
  raw-argument opt-in of R5 renders what survived R22 and cannot restore what it removed.

## Acceptance Examples

- AE1. **Covers R3, R11.** Given `ocsf-audit` wired once to the stderr exporter and once to
  the file exporter, when the three committed conformance vectors are replayed, the records
  recovered from both destinations are byte-identical to each other and to the vectors.
- AE2. **Covers R2, R4, R7.** Given `ocsf-audit` in `queued` delivery with the `block`
  policy, when 10,000 verdicts are driven through the engine from 8 concurrent connections,
  the exported stream has `stream_seq` 0 through 9,999 with no gap, the chain order equals the
  `stream_seq` order, every `prev_event` matches its predecessor's recomputed fingerprint,
  every signature verifies offline, and every record's event time lies between the request's
  arrival and the verdict rather than at drain time.
- AE3. **Covers R8, R16.** Given a queue of depth 64 and the `drop-counted` policy, when the
  exporter is stalled for the duration of 200 verdicts, the sink's drop counter and the number
  of `stream_seq` gaps the validator reports are equal, and the records on either side of each
  gap still verify.
- AE4. **Covers R9.** Given a route that does not resolve and a sink in `queued` delivery, the
  denial is stamped, delivered, and verifies like an allowed verdict.
- AE5. **Covers R17.** Given a `spill` policy and 500 serialized records in the spill buffer
  at shutdown, when the engine restarts, the 500 records are exported byte-identical under the
  old epoch before the first record of the new epoch, every one still verifies, and the new
  epoch opens at `stream_seq` 0. Given a reload instead of a restart, the outgoing executor's
  queue drains under its epoch before the new executor's first record is exported.
- AE6. **Covers R5.** Given `audit-logger` with default settings and a tool call whose
  arguments contain a secret, the exported record carries the argument's key and type and not
  its value. With the opt-in set, it carries the value, and the docs say so.
- AE7. **Covers R6.** Given a sink that declares no `read_agent` capability, the record it
  serializes through the queued path has no agent fields, exactly as the inline path filters
  today.
- AE8. **Covers R18.** The benchmark from R18 reports per-record engine cost for
  `audit-logger` and `ocsf-audit` (chained, signed) under inline delivery, and the same under
  queued delivery after the change, with the signature cost shown to have left the request
  path.
- AE9. **Covers R19, R20.** Given only the file exporter's output and the public key fetched
  by the key identifier in the record, the standalone validator reports fingerprint, signature,
  chain and stream checks as passing, with no PPE code on the machine.
- AE10. **Covers R5, R22.** Given a request carrying an `Authorization` header and a tool call
  whose arguments contain a secret, with `audit-logger` and `ocsf-audit` both attached and both
  set to the raw-argument opt-in (so the digest default of R5 is not what hides the secret),
  neither exported record contains the header value or the secret, both carry the removal
  marker naming the header, and the `ocsf-audit` record still verifies offline.

## Success Criteria

- `audit-logger` and `ocsf-audit` both run as serializers behind the same exporter trait, and
  neither emits a record that differs from what it emitted before the split.
- The queued path exists, is off by default, and every one of AE1 through AE10 is a named
  test or benchmark in the tree.
- A consumer holding exported bytes from any built-in exporter can verify an `ocsf-audit`
  record offline against the published contract without reading PPE source.
- A planner can sequence the exporter trait, the local exporters, the queue, and the
  benchmark without inventing an ordering rule, an overflow semantic, or a framing format.

## Scope Boundaries

- No anchoring, checkpoints, witnesses, transparency logs or ledgers. Those are consumers of
  the exported stream, not part of PPE. The ledger demo stays in the demos repository.
- No OTLP exporter in the first increment; its framing is an outstanding question below.
- No key rotation or key management policy beyond resolving a key by reference.
- No change to the OCSF record shape or to AID-EMIT-1; this document consumes the contract.
- No change to what the audit seam observes or to `AuditHandler`'s capability filtering. The
  stamp gains an event time and the sink view gains argument digests (R5, R7); both are
  additions to what is handed over, not to what is observed.

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
  recomputes over, so a spill buffer can neither be altered unnoticed nor needs chain state to
  resume after a restart. The cost is that spill cannot relieve a drain task that is itself
  the bottleneck; that case is `block` or `drop-counted`, in the open.
- **Local exporters first.** PPE has no collector stack to lean on, and the operators Teryl and
  Fred asked inside Red Hat all run one already. Local output into an existing collector is
  the shortest path to production and adds no network dependency to the data plane.
- **Batches carry no semantics.** The moment a batch boundary means something, a consumer has
  to reconstruct it, and a transport retry can change it. Records are the unit; batches are a
  transport optimization only.
- **Digest-only by default, for every sink.** Making this a serializer-layer rule rather than
  an `audit-logger` fix means a third-party sink inherits the safe default.
- **The engine redacts, the sink renders.** If each sink redacted for itself, the weakest sink
  would set the exposure and every new sink would reinvent the list. Done once in the engine,
  before the record exists, the rule is uniform across sinks and sits inside the hashed bytes,
  so verification is unaffected. Dropping or keyed-digesting, never masking, keeps records
  comparable without exposing anything.

## Dependencies / Assumptions

- #84 is merged and `emit_decision` is the single place a verdict is finalized and stamped.
- #12 lands the `ocsf-audit` serializer under `reference/plugins/` on the #84 head; this
  document assumes that plugin is the first sink with integrity requirements.
- #164 settles how a background drain task obtains an engine-tracked runtime and how an
  exporter holds a transport grant; R13 and R17 depend on its answer.
- #106 and #107 (serialize the decision log; record plugin id, kind and duration on a step)
  change what a serializer has available but not the split described here.
- The record contract for `ocsf-audit` is AID-EMIT-1 1.1.x as published in Levaj2000/AI-Identity
  (`docs/specs/aid-emit-1.md`) with its standalone validator. Praxis may vendor or link the
  validator; either satisfies R19.

## Outstanding Questions

### Deferred to Planning

- [Affects R1, R10][Technical] Exact trait shapes for serializer and exporter, and whether a
  serialized record is `Bytes` plus metadata or a small struct the exporter can inspect for
  routing without reading the body.
- [Affects R3][Needs research] OTLP framing that satisfies R3: the record as an opaque log
  body with stream fields as attributes keeps the bytes intact; mapping fields into
  structured attributes re-encodes them and breaks verification. Confirm the collector side
  can recover the body byte-for-byte.
- [Affects R4][Technical] Whether a chained serializer is one instance per `(epoch,
  stream_id)` or one instance guarding its chain state, given the engine today stamps one
  decision stream and one effect stream per host. And how the stamp and the enqueue become
  one step: a lock around `fetch_add` plus push, or a sequence-ordered channel.
- [Affects R7][Technical] Confirm where the stamp is assigned on the #84 head relative to the
  handoff point the queue would introduce, so nothing can be enqueued unstamped.
- [Affects R12][Technical] File exporter rotation, fsync cadence, and whether rotation is PPE's
  job or the collector's. Linux audit record format and size limits.
- [Affects R16, R17][Technical] Spill buffer format and location (the records are already
  framed per R3, so the buffer is the exporter's framing on disk), and how the spilled epoch is
  read back so the old epoch drains ahead of the new one on restart.
- [Affects R1, R5][Technical] The shape of the payload view a queued sink receives: the audit
  bytes already digested by the engine, plus the raw arguments only under the opt-in, and
  what an owned copy per queued sink costs on the request path.
- [Affects R18][Technical] Benchmark harness: what "per-record engine cost" measures, and
  whether the existing `panic_drive` style of driving a real engine through `load_config` is
  the right vehicle.
- [Affects R20][Technical] Whether the reference plugin resolves its signing key through
  `SecretProvider` directly or through a host-provided key handle, and how the key identifier
  in the record maps to a provider reference.
- [Affects R22][Technical] The operator-facing shape of the removal list (a fixed set plus an
  allowlist or denylist of header names and JSON paths), where the removal marker lives (a
  typed slot or `unmapped`), and whether the open-ended slots are filtered by path or by a
  value-level rule such as digesting every string above a length.
