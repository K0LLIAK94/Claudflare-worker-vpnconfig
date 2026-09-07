/**
 * Throne subscription bridge — KV-only edition.
 * Cloudflare binding: SUBSCRIPTIONS_KV (Workers KV namespace).
 * Optional secrets: REFRESH_TOKEN, GITHUB_TOKEN.
 * No Durable Objects, cron, external packages or stored credentials required.
 */
const REPOSITORY = "igareck/vpn-configs-for-russia";
const BRANCH = "main";
const API = `https://api.github.com/repos/${REPOSITORY}`;
const RAW = `https://raw.githubusercontent.com/${REPOSITORY}/`;
const CHECK_MS = 15 * 60 * 1000;
const RETRY_MS = 5 * 60 * 1000;
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES = 25 * 1024 * 1024;
const HEAD_KEY = "bridge:v3:head";
const SCOPES = ["all", "black", "white-cidr", "white-sni"];
const PATTERNS = {
  all: /^(?:BLACK_.*|WHITE-(?:CIDR|SNI)-.*|Vless-Reality-White-Lists-Rus-Mobile(?:-\d+)?)\.txt$/i,
  black: /^BLACK_.*\.txt$/i,
  "white-cidr": /^WHITE-CIDR-.*\.txt$/i,
  "white-sni": /^WHITE-SNI-.*\.txt$/i,
};
const PROXY_URI = /^(?!https?:\/\/)[a-z][a-z0-9+.-]*:\/\/\S+$/i;
const encoder = new TextEncoder();
let pendingRefresh = null; // Single-flight within this Worker isolate only.

function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}
function headers(extra = {}) {
  return {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "access-control-allow-origin": "*",
    ...extra,
  };
}
function responseError(message, status = 502) {
  return new Response(message, { status, headers: headers() });
}
function jsonResponse(data, status = 200) {
  return Response.json(data, { status, headers: headers() });
}
function validSha(sha) {
  return typeof sha === "string" && /^[a-f0-9]{40}$/i.test(sha);
}
function snapshotKey(sha) {
  return `bridge:v3:snapshot:${sha}`;
}
function toBase64Utf8(text) {
  const bytes = encoder.encode(text);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

async function githubJson(path, env) {
  const requestHeaders = {
    "user-agent": "throne-subscription-bridge/3.0",
    accept: "application/vnd.github+json",
  };
  if (env.GITHUB_TOKEN) requestHeaders.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  const response = await fetch(`${API}${path}`, {
    headers: requestHeaders,
    signal: AbortSignal.timeout(15000),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`GitHub API: HTTP ${response.status}`);
  return response.json();
}
async function latestCommit(env) {
  const data = await githubJson(`/commits/${BRANCH}`, env);
  if (!validSha(data.sha) || !validSha(data.commit?.tree?.sha)) {
    throw new Error("GitHub returned an invalid commit or tree SHA");
  }
  return { sha: data.sha, tree: data.commit.tree.sha };
}
async function discoverSources(treeSha, env) {
  // The immutable root tree is more reliable than parsing changing README markup.
  // It also automatically includes newly added standard root TXT files.
  const data = await githubJson(`/git/trees/${treeSha}`, env);
  if (data.truncated || !Array.isArray(data.tree)) {
    throw new Error("GitHub returned an incomplete repository tree");
  }
  const sources = data.tree
    .filter((item) => item.type === "blob" && PATTERNS.all.test(item.path))
    .map((item) => item.path)
    .sort();
  if (sources.length === 0 || sources.length > 64) {
    throw new Error(`Unexpected number of standard TXT sources: ${sources.length}`);
  }
  return sources;
}
async function loadSource(path, sha) {
  const url = `${RAW}${sha}/${encodeURIComponent(path)}`;
  const response = await fetch(url, {
    headers: { "user-agent": "throne-subscription-bridge/3.0" },
    signal: AbortSignal.timeout(20000),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  const declaredLength = Number(response.headers.get("content-length"));
  if (declaredLength > MAX_SOURCE_BYTES) throw new Error(`${path}: source too large`);
  const text = await response.text();
  if (encoder.encode(text).byteLength > MAX_SOURCE_BYTES) {
    throw new Error(`${path}: source too large`);
  }
  const proxies = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => PROXY_URI.test(line));
  if (proxies.length === 0) throw new Error(`${path}: no supported proxy URI lines`);
  return { path, proxies };
}
async function buildSnapshot(commit, env) {
  const sources = await discoverSources(commit.tree, env);
  const results = await Promise.allSettled(sources.map((path) => loadSource(path, commit.sha)));
  const errors = results
    .filter((result) => result.status === "rejected")
    .map((result) => errorText(result.reason));
  // Never publish a partially downloaded or empty aggregate.
  if (errors.length) throw new Error(`Source download failed: ${errors.join("; ")}`);
  const profiles = new Map();
  const counts = Object.fromEntries(SCOPES.map((scope) => [scope, 0]));
  const sourceStats = [];
  for (const result of results) {
    if (result.status !== "fulfilled") continue;
    const { path, proxies } = result.value;
    let mask = 1;
    if (PATTERNS.black.test(path)) mask |= 2;
    if (PATTERNS["white-cidr"].test(path)) mask |= 4;
    if (PATTERNS["white-sni"].test(path)) mask |= 8;
    sourceStats.push({ path, count: proxies.length });
    for (const uri of proxies) profiles.set(uri, (profiles.get(uri) || 0) | mask);
  }
  for (const mask of profiles.values()) {
    for (let i = 0; i < SCOPES.length; i++) if (mask & (1 << i)) counts[SCOPES[i]]++;
  }
  if (SCOPES.some((scope) => counts[scope] === 0)) {
    throw new Error("One or more subscription scopes are empty");
  }
  const snapshot = {
    schema: 3,
    sha: commit.sha,
    generatedAt: new Date().toISOString(),
    sources: sourceStats,
    counts,
    profiles: [...profiles],
  };
  const serialized = JSON.stringify(snapshot);
  if (encoder.encode(serialized).byteLength > MAX_SNAPSHOT_BYTES) {
    throw new Error("Aggregate exceeds the 25 MiB KV value limit");
  }
  return { snapshot, serialized };
}

async function getHead(env) {
  const head = await env.SUBSCRIPTIONS_KV.get(HEAD_KEY, { type: "json", cacheTtl: 60 });
  return head?.schema === 3 ? head : null;
}
async function getSnapshot(env, key) {
  if (!key || !/^bridge:v3:snapshot:[a-f0-9]{40}$/i.test(key)) return null;
  const snapshot = await env.SUBSCRIPTIONS_KV.get(key, { type: "json", cacheTtl: 60 });
  return snapshot?.schema === 3 && Array.isArray(snapshot.profiles) ? snapshot : null;
}
async function readReady(env, head) {
  if (!head) return null;
  const current = await getSnapshot(env, head.snapshotKey);
  if (current) return { snapshot: current, head, fallback: false };
  const previous = await getSnapshot(env, head.previousKey);
  if (previous) return { snapshot: previous, head, fallback: true };
  return null;
}
function isFresh(head, now = Date.now()) {
  return head && Number.isFinite(head.nextCheckAt) && now < head.nextCheckAt;
}
async function saveHead(env, head) {
  await env.SUBSCRIPTIONS_KV.put(HEAD_KEY, JSON.stringify(head));
}

async function refresh(env, initialHead, force = false) {
  // Re-read inside single-flight: another request in this isolate may have updated it.
  let head = await getHead(env) || initialHead;
  const ready = await readReady(env, head);
  if (!force && ready && isFresh(head)) return { action: "fresh", head, snapshot: ready.snapshot };
  const checkedAt = new Date().toISOString();
  try {
    const commit = await latestCommit(env);
    if (ready && head.sha === commit.sha && ready.snapshot.sha === commit.sha) {
      head = { ...head, checkedAt, nextCheckAt: Date.now() + CHECK_MS, lastCheckResult: "unchanged", lastError: null };
      await saveHead(env, head);
      return { action: "unchanged", head, snapshot: ready.snapshot };
    }
    const { snapshot, serialized } = await buildSnapshot(commit, env);
    const key = snapshotKey(commit.sha);
    // Immutable snapshot first, then the small pointer. A failed build cannot
    // replace the previous working version. No cross-region KV transaction exists.
    await env.SUBSCRIPTIONS_KV.put(key, serialized);
    head = {
      schema: 3,
      sha: commit.sha,
      snapshotKey: key,
      previousKey: head?.snapshotKey !== key ? head?.snapshotKey || null : head?.previousKey || null,
      generatedAt: snapshot.generatedAt,
      checkedAt,
      nextCheckAt: Date.now() + CHECK_MS,
      lastCheckResult: ready ? "updated" : "initialized",
      lastError: null,
      counts: snapshot.counts,
    };
    await saveHead(env, head);
    return { action: head.lastCheckResult, head, snapshot };
  } catch (error) {
    const message = errorText(error);
    if (!ready) throw error;
    const failedHead = {
      ...head,
      checkedAt,
      nextCheckAt: Date.now() + RETRY_MS,
      lastCheckResult: "error",
      lastError: message,
    };
    // A failed metadata write must not turn a usable stale cache into a 502.
    try { await saveHead(env, failedHead); } catch { /* Keep the old snapshot. */ }
    return { action: "stale", head: failedHead, snapshot: ready.snapshot };
  }
}
async function ensureReady(env, force = false) {
  const head = await getHead(env);
  const ready = await readReady(env, head);
  if (!force && ready && isFresh(head)) return { action: "fresh", head, snapshot: ready.snapshot };
  if (!pendingRefresh) {
    pendingRefresh = refresh(env, head, force).finally(() => { pendingRefresh = null; });
  }
  try {
    return await pendingRefresh;
  } catch (error) {
    if (ready) return { action: "stale", head, snapshot: ready.snapshot, error: errorText(error) };
    throw error;
  }
}
function renderSubscription(snapshot, scope, format) {
  const bit = 1 << SCOPES.indexOf(scope);
  const lines = snapshot.profiles.filter((entry) => entry[1] & bit).map((entry) => entry[0]);
  const body = `${lines.join("\n")}\n`;
  if (format === "base64") return toBase64Utf8(body);
  return [
    `# profile-title: Universal | Igareck ${scope} aggregate`,
    "# profile-update-interval: 60",
    `# Generated: ${snapshot.generatedAt}`,
    `# Upstream commit: ${snapshot.sha}`,
    `# Unique proxies: ${lines.length}`,
    body,
  ].join("\n");
}
async function authorized(request, env) {
  if (!env.REFRESH_TOKEN) return false;
  const actual = request.headers.get("authorization") || "";
  const expected = `Bearer ${env.REFRESH_TOKEN}`;
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(actual)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!["/", "/subscription", "/status", "/refresh"].includes(path)) {
      return responseError("Not found. Use /subscription or /status", 404);
    }
    if (!env.SUBSCRIPTIONS_KV) {
      return responseError("Missing SUBSCRIPTIONS_KV binding. See README.md", 503);
    }
    if (path === "/refresh") {
      if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: headers({ allow: "POST" }) });
      if (!(await authorized(request, env))) return responseError("Unauthorized", 401);
    } else if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405, headers: headers({ allow: "GET" }) });
    }
    const scope = url.searchParams.get("scope") || "all";
    const format = url.searchParams.get("format") || "base64";
    if (!Object.prototype.hasOwnProperty.call(PATTERNS, scope)) return responseError("Unknown scope", 400);
    if (!["base64", "plain"].includes(format)) return responseError("Unknown format", 400);
    try {
      if (path === "/status") {
        const head = await getHead(env);
        const ready = await readReady(env, head);
        return jsonResponse({
          ok: Boolean(ready), scope,
          sha: ready?.snapshot.sha || null,
          generatedAt: ready?.snapshot.generatedAt || null,
          checkedAt: head?.checkedAt || null,
          nextCheckAt: head?.nextCheckAt ? new Date(head.nextCheckAt).toISOString() : null,
          lastCheckResult: head?.lastCheckResult || null,
          lastError: head?.lastError || null,
          checkIntervalMinutes: 15,
          uniqueProxies: ready?.snapshot.counts?.[scope] || 0,
          sources: ready?.snapshot.sources || [],
          fallback: ready?.fallback || false,
        });
      }
      const result = await ensureReady(env, path === "/refresh");
      if (path === "/refresh") return jsonResponse({ ok: true, action: result.action, sha: result.snapshot.sha, generatedAt: result.snapshot.generatedAt });
      return new Response(renderSubscription(result.snapshot, scope, format), {
        headers: headers({
          "x-subscription-sha": result.snapshot.sha,
          "x-subscription-cache": result.action,
        }),
      });
    } catch (error) {
      return responseError(`Subscription unavailable: ${errorText(error)}`);
    }
  },
};
