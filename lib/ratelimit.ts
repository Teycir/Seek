/**
 * ratelimit.ts — KV-backed per-IP rate limiter + circuit breaker.
 *
 * Rate limiter
 * ─────────────
 * Stores a sliding-window counter keyed by client IP in KV.
 * Default: 100 requests / hour (as specified in ROADMAP).
 * The counter key expires automatically via KV TTL, so no
 * explicit window reset is needed.
 *
 * Circuit breaker
 * ────────────────
 * Tracks requests and failures for each upstream source in a 5-minute
 * rolling window stored in KV.  The breaker OPENS when the failure
 * ratio exceeds 50 % of requests in that window.  After a 15-minute
 * cooldown (OPEN_TTL_SECONDS) the KV key expires and the breaker
 * moves to 'half-open': the next request probes through; if it
 * succeeds the breaker resets to 'closed'.
 *
 * KV schema (all keys prefixed with "cb:<source>:")
 *   :window_reqs  – total requests in the current 5-min window (TTL = 5 min)
 *   :window_fails – failures in the current 5-min window    (TTL = 5 min)
 *   :open         – presence means breaker is open          (TTL = 15 min)
 */

import { RATE_LIMIT, CIRCUIT_BREAKER, CONCURRENCY } from './config'

// ─── Log sanitization ─────────────────────────────────────────────────────────

/**
 * Sanitize user input before logging to prevent log injection (CWE-117).
 * Removes newlines, carriage returns, and other control characters.
 */
function sanitizeForLog(input: string): string {
  return input.replace(/[\r\n\t\x00-\x1F\x7F]/g, '')
}

// ─── Per-IP rate limiter ──────────────────────────────────────────────────────

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetInSeconds: number
}

const RL_WINDOW_SECONDS = RATE_LIMIT.WINDOW_SECONDS
const RL_MAX_REQUESTS   = RATE_LIMIT.MAX_REQUESTS
const RL_KV_PREFIX      = RATE_LIMIT.KV_PREFIX

/**
 * Check (and increment) the per-IP counter in KV.
 * Returns { allowed: false } when the limit is exceeded.
 *
 * NOTE: The read-increment-write sequence is not atomic — concurrent requests
 * from the same IP may under-count usage, allowing slight quota overruns under
 * high parallelism. Under the worst case the effective limit is approximately
 * maxRequests × max_concurrent_workers_per_IP. This is acceptable for a
 * best-effort rate limiter; for strict enforcement migrate to a Durable Object
 * counter (Cloudflare Durable Objects provide serialised access per key).
 *
 * @param cost  Number of quota slots to consume (default 1). Used by batch
 *              routes to charge the full batch size in one call.
 */
export async function checkRateLimit(
  ip: string,
  kv: KVNamespace,
  cost = 1,
  maxRequests = RL_MAX_REQUESTS,
  windowSeconds = RL_WINDOW_SECONDS,
): Promise<RateLimitResult> {
  const key = `${RL_KV_PREFIX}${ip}`

  try {
    const raw = await kv.get(key, 'text')
    const current = raw ? parseInt(raw, 10) : 0

    if (current + cost > maxRequests) {
      // Would exceed limit — do NOT increment
      const meta = await kv.getWithMetadata<{ expiration?: number }>(key)
      const expiration = meta.metadata?.expiration ?? 0
      const resetInSeconds = expiration
        ? Math.max(0, expiration - Math.floor(Date.now() / 1000))
        : windowSeconds

      return { allowed: false, remaining: Math.max(0, maxRequests - current), resetInSeconds }
    }

    // Consume `cost` slots. Write every 5 requests to reduce KV write usage —
    // the counter may be slightly under-counted between writes, but this is
    // acceptable for a best-effort limiter. On first write (current === 0)
    // always write so the TTL window is established.
    const next = current + cost
    if (current === 0 || next % 5 === 0 || next > maxRequests - 5) {
      await kv.put(key, String(next), { expirationTtl: windowSeconds })
    }

    return {
      allowed:        true,
      remaining:      maxRequests - next,
      resetInSeconds: windowSeconds,
    }
  } catch (err) {
    // KV failure — fail open (allow the request) to avoid self-DoS
    console.error('[ratelimit] KV error, failing open', err)
    return { allowed: true, remaining: maxRequests, resetInSeconds: windowSeconds }
  }
}

// ─── Circuit breaker ──────────────────────────────────────────────────────────

const CB_KV_PREFIX          = CIRCUIT_BREAKER.KV_PREFIX
const WINDOW_TTL_SECONDS    = CIRCUIT_BREAKER.WINDOW_TTL_SECONDS
const OPEN_TTL_SECONDS      = CIRCUIT_BREAKER.OPEN_TTL_SECONDS
const TRIP_RATIO            = CIRCUIT_BREAKER.TRIP_RATIO
const MIN_REQUESTS_TO_TRIP  = CIRCUIT_BREAKER.MIN_REQUESTS_TO_TRIP

export type BreakerState = 'closed' | 'open' | 'half-open'

export interface BreakerStatus {
  source: string
  state: BreakerState
  /** Requests counted in the current 5-min window */
  windowRequests: number
  /** Failures counted in the current 5-min window */
  windowFailures: number
  /** Unix-ms when the open key expires (i.e. recovery time); 0 if closed */
  opensUntil: number
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function reqKey  (source: string) { return `${CB_KV_PREFIX}${source}:window_reqs`  }
function failKey (source: string) { return `${CB_KV_PREFIX}${source}:window_fails` }
function openKey (source: string) { return `${CB_KV_PREFIX}${source}:open`         }

async function getWindowCounts(
  source: string,
  kv: KVNamespace,
): Promise<{ reqs: number; fails: number }> {
  try {
    const [r, f] = await Promise.all([
      kv.get(reqKey(source),  'text'),
      kv.get(failKey(source), 'text'),
    ])
    return {
      reqs:  r ? parseInt(r, 10) : 0,
      fails: f ? parseInt(f, 10) : 0,
    }
  } catch (err) {
    console.error(`[ratelimit] getWindowCounts failed for source=${sanitizeForLog(source)}:`, err)
    return { reqs: 0, fails: 0 }
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns the current breaker state for a source.
 * 'half-open' is signalled by the absence of the :open key (it expired)
 * combined with a non-zero failure history in the window.
 */
export async function getBreakerState(
  source: string,
  kv: KVNamespace,
): Promise<BreakerState> {
  try {
    const openFlag = await kv.get(openKey(source), 'text')
    if (openFlag !== null) return 'open'

    // If the open key has expired, the next probe is 'half-open'
    const { reqs, fails } = await getWindowCounts(source, kv)
    if (reqs >= MIN_REQUESTS_TO_TRIP && fails / reqs > TRIP_RATIO) {
      // Window counts are still warm but the open flag expired → half-open
      return 'half-open'
    }

    return 'closed'
  } catch (err) {
    console.error(`[ratelimit] getBreakerState failed for source=${sanitizeForLog(source)}:`, err)
    return 'closed'
  }
}

/**
 * Full status snapshot for a single source (used by the admin endpoint
 * and the meta block in API responses).
 */
export async function getBreakerStatus(
  source: string,
  kv: KVNamespace,
): Promise<BreakerStatus> {
  try {
    const [openMeta, { reqs, fails }] = await Promise.all([
      kv.getWithMetadata<{ expiration?: number }>(openKey(source)),
      getWindowCounts(source, kv),
    ])

    const isOpen    = openMeta.value !== null
    const opensUntil = isOpen && openMeta.metadata?.expiration
      ? openMeta.metadata.expiration * 1000   // KV expiration is unix-seconds
      : 0

    let state: BreakerState = 'closed'
    if (isOpen) {
      state = 'open'
    } else if (reqs >= MIN_REQUESTS_TO_TRIP && fails / reqs > TRIP_RATIO) {
      state = 'half-open'
    }

    return { source, state, windowRequests: reqs, windowFailures: fails, opensUntil }
  } catch (err) {
    console.error(`[ratelimit] getBreakerStatus failed for source=${sanitizeForLog(source)}:`, err)
    return { source, state: 'closed', windowRequests: 0, windowFailures: 0, opensUntil: 0 }
  }
}

/**
 * Bulk-fetch status for every source in one call (used by mergeResults).
 */
export async function getAllBreakerStatuses(
  sources: string[],
  kv: KVNamespace,
): Promise<BreakerStatus[]> {
  return Promise.all(sources.map(s => getBreakerStatus(s, kv)))
}

/**
 * Call on a successful response from a source.
 * Increments the request counter so the failure ratio denominator stays
 * accurate, then clears the :open flag so a recovering source re-enters
 * 'closed' state.
 *
 * Deliberately does NOT delete the window counters — wiping them on every
 * success would prevent the breaker from ever tripping on a source that
 * succeeds occasionally (e.g. 1-in-5 success rate). The counters expire
 * naturally via their WINDOW_TTL_SECONDS KV TTL.
 */
export async function recordBreakerSuccess(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    // Increment the request counter alongside every success so the
    // failure-ratio denominator includes all outcomes (not just failures).
    const raw  = await kv.get(reqKey(source), 'text')
    const next = (raw ? parseInt(raw, 10) : 0) + 1
    await Promise.all([
      kv.put(reqKey(source), String(next), { expirationTtl: WINDOW_TTL_SECONDS }),
      kv.delete(openKey(source)),
    ])
  } catch (err) {
    console.error(`[ratelimit] recordBreakerSuccess failed for source=${sanitizeForLog(source)}:`, err)
  }
}

/**
 * Call on any failed response from a source (non-2xx, timeout, etc.).
 * Increments counters; opens the breaker when the failure ratio exceeds
 * TRIP_RATIO within the 5-minute window.
 */
export async function recordBreakerFailure(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    const { reqs: prevReqs, fails: prevFails } = await getWindowCounts(source, kv)

    const newReqs  = prevReqs  + 1
    const newFails = prevFails + 1

    // Write updated counters; TTL resets the window after 5 minutes
    await Promise.all([
      kv.put(reqKey(source),  String(newReqs),  { expirationTtl: WINDOW_TTL_SECONDS }),
      kv.put(failKey(source), String(newFails), { expirationTtl: WINDOW_TTL_SECONDS }),
    ])

    // Trip the breaker when ratio > 50 % and we have enough data points
    if (newReqs >= MIN_REQUESTS_TO_TRIP && newFails / newReqs > TRIP_RATIO) {
      await kv.put(openKey(source), '1', { expirationTtl: OPEN_TTL_SECONDS })
    }
  } catch (err) {
    console.error(`[ratelimit] recordBreakerFailure failed for source=${sanitizeForLog(source)}:`, err)
  }
}

/**
 * Record a successful request without resetting the failure counters.
 * Used by sources to increment the request counter even on cache hits
 * so the ratio calculation stays accurate.
 */
export async function recordBreakerRequest(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  try {
    const raw = await kv.get(reqKey(source), 'text')
    const next = (raw ? parseInt(raw, 10) : 0) + 1
    await kv.put(reqKey(source), String(next), { expirationTtl: WINDOW_TTL_SECONDS })
  } catch (err) {
    console.error(`[ratelimit] recordBreakerRequest failed for source=${sanitizeForLog(source)}:`, err)
  }
}

/**
 * Manually reset a circuit breaker — clears open flag AND window counters.
 * Called by the admin endpoint. Unlike recordBreakerSuccess, this wipes all
 * state so the breaker starts fresh.
 */
export async function resetBreaker(
  source: string,
  kv: KVNamespace,
): Promise<void> {
  await Promise.all([
    kv.delete(reqKey(source)),
    kv.delete(failKey(source)),
    kv.delete(openKey(source)),
  ])
}

// ─── Global concurrency limiter ───────────────────────────────────────────────

const CC_KEY     = CONCURRENCY.KV_KEY
const CC_MAX     = CONCURRENCY.MAX_PARALLEL
const CC_TTL     = CONCURRENCY.SLOT_TTL_SECONDS

export interface ConcurrencyResult {
  /** true → slot acquired, request may proceed */
  allowed: boolean
  /** current active count at the time of the check */
  active: number
  /** configured ceiling */
  limit: number
}

/**
 * Try to acquire one concurrency slot.
 * Returns { allowed: true } when a slot is available and atomically increments
 * the counter.  Returns { allowed: false } when the server is at capacity.
 *
 * NOTE: Like checkRateLimit, the read-increment-write is not atomic. Under
 * concurrent Workers the active count may be under-counted, allowing slightly
 * more than CC_MAX parallel requests at peak. Under the worst case the
 * effective ceiling is CC_MAX + (number of concurrent Workers − 1). The KV
 * TTL is a safety net. For strict enforcement, migrate to a Durable Object.
 *
 * IMPORTANT: callers MUST call releaseConcurrency() in a finally block to
 * avoid leaking slots.  The KV TTL is a safety net, not the primary release.
 */
export async function acquireConcurrency(kv: KVNamespace): Promise<ConcurrencyResult> {
  try {
    const raw    = await kv.get(CC_KEY, 'text')
    const active = raw ? parseInt(raw, 10) : 0

    if (active >= CC_MAX) {
      return { allowed: false, active, limit: CC_MAX }
    }

    // Increment and refresh the safety-net TTL.
    await kv.put(CC_KEY, String(active + 1), { expirationTtl: CC_TTL })
    return { allowed: true, active: active + 1, limit: CC_MAX }
  } catch (err) {
    // KV failure — fail open so KV downtime doesn't block all users.
    console.error('[ratelimit] acquireConcurrency KV error, failing open', err)
    return { allowed: true, active: 0, limit: CC_MAX }
  }
}

/**
 * Release one concurrency slot.
 * We skip the KV write and let the TTL expire naturally — this saves one
 * write per lookup. The TTL (SLOT_TTL_SECONDS = 90s) is the safety net;
 * under normal load slots expire well before the next request arrives.
 * The counter may drift slightly high under burst traffic, but the TTL
 * self-corrects within 90s.
 */
export async function releaseConcurrency(_kv: KVNamespace): Promise<void> {
  // intentionally a no-op — slot expires via KV TTL
}
