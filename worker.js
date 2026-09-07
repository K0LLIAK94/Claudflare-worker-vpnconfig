/**
 * Throne subscription bridge for Cloudflare Workers.
 *
 * Bindings required:
 *   SUBSCRIPTIONS_KV  -> Cloudflare KV namespace
 *   UPDATE_LOCK       -> Durable Object namespace using class UpdateLock
 *
 * Refresh strategy:
 *   - VPN clients read the ready subscription from KV.
 *   - GitHub is checked at most once every 15 minutes.
 *   - The upstream main-branch commit SHA is compared with the cached SHA.
 *   - If SHA is unchanged, no TXT feeds are downloaded.
 *   - If SHA changed, all supported feeds are downloaded once and all scopes
 *     are rebuilt atomically from the same upstream snapshot.
 *   - If GitHub is unavailable, the last successful subscription stays usable.
 */

const REPOSITORY = "igareck/vpn-configs-for-russia";
const BRANCH = "main";
const RAW_BASE = `https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/`;
const README_URL = `${RAW_BASE}README.md`;
const COMMIT_URL = `https://api.github.com/repos/${REPOSITORY}/commits/${BRANCH}`;

const CHECK_INTERVAL_MS = 15 * 60 * 1000;
const USER_AGENT = "throne-subscription-bridge/2.0";
const META_KEY = "meta";
const SCOPES = ["all", "black", "white-cidr", "white-sni"];

const FALLBACK_SOURCES = [
  "BLACK_SS+All_RUS.txt",
  "BLACK_SS_WEAK_DPI_RUS.txt",
  "BLACK_VLESS_RUS.txt",
  "BLACK_VLESS_RUS_mobile.txt",
  "Vless-Reality-White-Lists-Rus-Mobile.txt",
  "WHITE-CIDR-RU-all.txt",
  "WHITE-CIDR-RU-checked.txt",
  "WHITE-SNI-RU-all.txt",
];

const PROXY_URI = /^(?!https?:\/\/)[a-z][a-z0-9+.-]*:\/\/\S+$/i;

const SCOPE_PATTERNS = {
  all: /^(?:BLACK_.*|WHITE-(?:CIDR|SNI)-.*|Vless-Reality-White-Lists-Rus-Mobile)\.txt$/i,
  black: /^BLACK_.*\.txt$/i,
  "white-cidr": /^WHITE-CIDR-.*\.txt$/i,
  "white-sni": /^WHITE-SNI-.*\.txt$/i,
};

function subscriptionKey(scope, format) {
  return `subscription:${scope}:${format}`;
}

function subscriptionHeaders(extra = {}) {
  return {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "access-control-allow-origin": "*",
    ...extra,
  };
}

function jsonHeaders() {
  return {
    "cache-control": "no-store, max-age=0",
    "access-control-allow-origin": "*",
  };
}

function toBase64Utf8(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";

  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }

  return btoa(binary);
}

function normalizeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function validateScope(scope) {
  return Object.prototype.hasOwnProperty.call(SCOPE_PATTERNS, scope);
}

async function fetchLatestCommitSha() {
  const response = await fetch(COMMIT_URL, {
    headers: {
      "user-agent": USER_AGENT,
      accept: "application/vnd.github+json",
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub commit check: HTTP ${response.status}`);
  }

  const data = await response.json();
  if (!data || typeof data.sha !== "string" || !data.sha) {
    throw new Error("GitHub commit check returned no SHA");
  }

  return data.sha;
}

async function discoverSources() {
  try {
    const response = await fetch(README_URL, {
      headers: { "user-agent": USER_AGENT },
    });

    if (!response.ok) {
      throw new Error(`README: HTTP ${response.status}`);
    }

    const readme = await response.text();
    const listedPaths = new Set();
    const link = /https?:\/\/(?:raw\.githack\.com|raw\.githubusercontent\.com)\/igareck\/vpn-configs-for-russia\/(?:main|refs\/heads\/main)\/([^\s)"']+\.txt)/gi;

    let match;
    while ((match = link.exec(readme)) !== null) {
      let path;
      try {
        path = decodeURIComponent(match[1]).split("?")[0];
      } catch {
        continue;
      }

      if (!path.includes("/") && SCOPE_PATTERNS.all.test(path)) {
        listedPaths.add(path);
      }
    }

    if (listedPaths.size > 0) {
      return [...listedPaths];
    }
  } catch {
    // Fallback keeps the last known standard source set available when README
    // discovery fails temporarily.
  }

  return [...FALLBACK_SOURCES];
}

async function loadSource(path) {
  const url = `${RAW_BASE}${path.split("/").map(encodeURIComponent).join("/")}`;
  const response = await fetch(url, {
    headers: { "user-agent": USER_AGENT },
  });

  if (!response.ok) {
    throw new Error(`${path}: HTTP ${response.status}`);
  }

  const proxies = (await response.text())
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => PROXY_URI.test(line));

  return { path, proxies };
}

async function buildAllSubscriptions(commitSha) {
  const sources = await discoverSources();
  const results = await Promise.allSettled(sources.map(loadSource));
  const loaded = [];
  const errors = [];

  for (const result of results) {
    if (result.status === "fulfilled") {
      loaded.push(result.value);
    } else {
      errors.push(normalizeError(result.reason));
    }
  }

  if (loaded.length === 0) {
    throw new Error(`All upstream feeds are unavailable: ${errors.join("; ")}`);
  }

  const generatedAt = new Date().toISOString();
  const subscriptions = {};
  const scopeStats = {};

  for (const scope of SCOPES) {
    const pattern = SCOPE_PATTERNS[scope];
    const unique = new Set();
    const usedSources = [];

    for (const source of loaded) {
      if (!pattern.test(source.path)) continue;
      usedSources.push(source.path);
      for (const proxy of source.proxies) unique.add(proxy);
    }

    if (unique.size === 0) {
      throw new Error(`Scope ${scope} produced zero proxy profiles`);
    }

    const proxyBody = `${[...unique].join("\n")}\n`;
    const headerLines = [
      `# profile-title: Universal | Igareck ${scope} aggregate`,
      "# profile-update-interval: 60",
      `# Generated: ${generatedAt}`,
      `# Upstream commit: ${commitSha}`,
      `# Unique proxies: ${unique.size}`,
    ];

    if (errors.length > 0) {
      headerLines.push(`# Unavailable source(s): ${errors.join("; ")}`);
    }

    subscriptions[scope] = {
      plain: `${headerLines.join("\n")}\n${proxyBody}`,
      base64: toBase64Utf8(proxyBody),
    };

    scopeStats[scope] = {
      uniqueProxies: unique.size,
      sources: usedSources,
    };
  }

  return {
    subscriptions,
    scopeStats,
    sources,
    errors,
    generatedAt,
  };
}

async function getMeta(env) {
  return (await env.SUBSCRIPTIONS_KV.get(META_KEY, "json")) || null;
}

async function hasCachedSubscription(env, scope, format) {
  return (await env.SUBSCRIPTIONS_KV.get(subscriptionKey(scope, format))) !== null;
}

function checkIsFresh(meta, now = Date.now()) {
  if (!meta || !meta.lastCheckedAt) return false;
  const checkedAt = Date.parse(meta.lastCheckedAt);
  return Number.isFinite(checkedAt) && now - checkedAt < CHECK_INTERVAL_MS;
}

async function refreshThroughLock(env, force = false) {
  const id = env.UPDATE_LOCK.idFromName("global-subscription-refresh");
  const stub = env.UPDATE_LOCK.get(id);
  const url = force ? "https://lock.internal/refresh?force=1" : "https://lock.internal/refresh";
  const response = await stub.fetch(url);

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.json();
}

async function ensureSubscription(env, scope, format) {
  const meta = await getMeta(env);
  const cached = await hasCachedSubscription(env, scope, format);

  if (cached && checkIsFresh(meta)) {
    return { meta, refresh: null };
  }

  try {
    const refresh = await refreshThroughLock(env, false);
    return { meta: await getMeta(env), refresh };
  } catch (error) {
    // A stale but valid subscription is preferable to breaking every client
    // during a transient GitHub/API outage.
    if (cached) {
      return {
        meta: await getMeta(env),
        refresh: { action: "stale-cache", error: normalizeError(error) },
      };
    }
    throw error;
  }
}

export class UpdateLock {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const force = url.searchParams.get("force") === "1";

    return this.state.blockConcurrencyWhile(async () => {
      const now = new Date();
      const currentMeta = await getMeta(this.env);

      if (!force && currentMeta && checkIsFresh(currentMeta, now.getTime())) {
        return Response.json({
          ok: true,
          action: "recently-checked",
          sha: currentMeta.sha || null,
        });
      }

      try {
        const latestSha = await fetchLatestCommitSha();

        if (currentMeta?.sha === latestSha) {
          const meta = {
            ...currentMeta,
            lastCheckedAt: now.toISOString(),
            lastCheckResult: "unchanged",
            lastError: null,
          };
          await this.env.SUBSCRIPTIONS_KV.put(META_KEY, JSON.stringify(meta));

          return Response.json({
            ok: true,
            action: "unchanged",
            sha: latestSha,
          });
        }

        const build = await buildAllSubscriptions(latestSha);

        const writes = [];
        for (const scope of SCOPES) {
          writes.push(
            this.env.SUBSCRIPTIONS_KV.put(
              subscriptionKey(scope, "plain"),
              build.subscriptions[scope].plain,
            ),
            this.env.SUBSCRIPTIONS_KV.put(
              subscriptionKey(scope, "base64"),
              build.subscriptions[scope].base64,
            ),
          );
        }
        await Promise.all(writes);

        const meta = {
          sha: latestSha,
          generatedAt: build.generatedAt,
          lastCheckedAt: now.toISOString(),
          lastSuccessfulUpdateAt: now.toISOString(),
          lastCheckResult: currentMeta?.sha ? "updated" : "initialized",
          lastError: null,
          failedSources: build.errors,
          discoveredSources: build.sources,
          scopes: build.scopeStats,
        };

        // Metadata is written last. Readers therefore never see a new SHA before
        // all subscription bodies have been stored successfully.
        await this.env.SUBSCRIPTIONS_KV.put(META_KEY, JSON.stringify(meta));

        return Response.json({
          ok: true,
          action: currentMeta?.sha ? "updated" : "initialized",
          sha: latestSha,
          generatedAt: build.generatedAt,
        });
      } catch (error) {
        const message = normalizeError(error);
        const failedMeta = {
          ...(currentMeta || {}),
          lastCheckedAt: now.toISOString(),
          lastCheckResult: "error",
          lastError: message,
        };
        await this.env.SUBSCRIPTIONS_KV.put(META_KEY, JSON.stringify(failedMeta));

        return new Response(`Subscription refresh failed: ${message}`, {
          status: 502,
          headers: subscriptionHeaders(),
        });
      }
    });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method !== "GET") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { allow: "GET" },
      });
    }

    if (
      url.pathname !== "/" &&
      url.pathname !== "/subscription" &&
      url.pathname !== "/status" &&
      url.pathname !== "/refresh"
    ) {
      return new Response("Not found. Use /subscription, /status, or /refresh", {
        status: 404,
      });
    }

    const scope = url.searchParams.get("scope") || "all";
    const format = url.searchParams.get("format") || "base64";

    if (!validateScope(scope)) {
      return new Response("Unknown scope. Use all, black, white-cidr, or white-sni", {
        status: 400,
      });
    }

    if (format !== "base64" && format !== "plain") {
      return new Response("Unknown format. Use base64 or plain", { status: 400 });
    }

    try {
      if (url.pathname === "/status") {
        const meta = await getMeta(env);
        const cachedPlain = await hasCachedSubscription(env, scope, "plain");
        const cachedBase64 = await hasCachedSubscription(env, scope, "base64");

        return Response.json(
          {
            ok: Boolean(meta && (cachedPlain || cachedBase64)),
            scope,
            sha: meta?.sha || null,
            generatedAt: meta?.generatedAt || null,
            lastCheckedAt: meta?.lastCheckedAt || null,
            lastSuccessfulUpdateAt: meta?.lastSuccessfulUpdateAt || null,
            lastCheckResult: meta?.lastCheckResult || null,
            lastError: meta?.lastError || null,
            checkIntervalMinutes: CHECK_INTERVAL_MS / 60000,
            cache: {
              plain: cachedPlain,
              base64: cachedBase64,
            },
            scopeInfo: meta?.scopes?.[scope] || null,
            failedSources: meta?.failedSources || [],
            discoveredSources: meta?.discoveredSources || [],
          },
          { headers: jsonHeaders() },
        );
      }

      if (url.pathname === "/refresh") {
        const refresh = await refreshThroughLock(env, true);
        return Response.json(refresh, { headers: jsonHeaders() });
      }

      const state = await ensureSubscription(env, scope, format);
      const body = await env.SUBSCRIPTIONS_KV.get(subscriptionKey(scope, format));

      if (body === null) {
        throw new Error(`No cached ${scope}/${format} subscription is available`);
      }

      return new Response(body, {
        headers: subscriptionHeaders({
          "x-subscription-sha": state.meta?.sha || "unknown",
          "x-subscription-cache": state.refresh?.action || "fresh",
        }),
      });
    } catch (error) {
      return new Response(`Upstream subscription error: ${normalizeError(error)}`, {
        status: 502,
        headers: subscriptionHeaders(),
      });
    }
  },
};
