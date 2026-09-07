/**
 * Throne subscription bridge.
 *
 * Deploy this file as a Cloudflare Worker. The /subscription endpoint
 * discovers the standard feeds in igareck's repository, combines them into
 * one plain-text subscription, and does not store proxy URLs on the Worker.
 */
const REPOSITORY = "igareck/vpn-configs-for-russia";
const BRANCH = "main";
const RAW_BASE = `https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/`;
const README_URL = `${RAW_BASE}README.md`;
// Used only if the README cannot be downloaded. Keeping this fallback means a
// transient GitHub error cannot make the subscription unavailable.
const FALLBACK_SOURCES = {
  all: [
    "BLACK_SS+All_RUS.txt",
    "BLACK_SS_WEAK_DPI_RUS.txt",
    "BLACK_VLESS_RUS.txt",
    "BLACK_VLESS_RUS_mobile.txt",
    "Vless-Reality-White-Lists-Rus-Mobile.txt",
    "WHITE-CIDR-RU-all.txt",
    "WHITE-CIDR-RU-checked.txt",
    "WHITE-SNI-RU-all.txt",
  ],
  black: ["BLACK_VLESS_RUS.txt", "BLACK_SS+All_RUS.txt"],
  "white-cidr": ["WHITE-CIDR-RU-all.txt", "WHITE-CIDR-RU-checked.txt"],
  "white-sni": ["WHITE-SNI-RU-all.txt"],
};
// New proxy schemes are accepted automatically. HTTP(S) links are excluded so
// links in comments/readmes cannot become proxy profiles by accident.
const PROXY_URI = /^(?!https?:\/\/)[a-z][a-z0-9+.-]*:\/\/\S+$/i;
const SCOPES = {
  all: /^(?:BLACK_.*|WHITE-(?:CIDR|SNI)-.*|Vless-Reality-White-Lists-Rus-Mobile)\.txt$/i,
  black: /^BLACK_.*\.txt$/i,
  "white-cidr": /^WHITE-CIDR-.*\.txt$/i,
  "white-sni": /^WHITE-SNI-.*\.txt$/i,
};
function subscriptionHeaders() {
  return {
    "content-type": "text/plain; charset=utf-8",
    // Do not let Throne or an intermediary reuse an old subscription.
    "cache-control": "no-store, max-age=0",
    "access-control-allow-origin": "*",
  };
}
function toBase64Utf8(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  // btoa accepts bytes only; chunking avoids a call-stack overflow on large feeds.
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}
async function discoverSources(scope) {
  const pattern = SCOPES[scope];
  if (!pattern) throw new Error("Unknown scope. Use all, black, white-cidr, or white-sni");
  try {
    // GitHub's API is rate-limited for Workers. The repository README already
    // lists every supported subscription, and raw.githubusercontent.com is not
    // subject to that API limit.
    const response = await fetch(README_URL, {
      headers: { "user-agent": "universal-subscription-bridge/1.1" },
    });
    if (!response.ok) throw new Error(`README: HTTP ${response.status}`);
    const readme = await response.text();
    const listedPaths = new Set();
    const link = /https?:\/\/(?:raw\.githack\.com|raw\.githubusercontent\.com)\/igareck\/vpn-configs-for-russia\/(?:main|refs\/heads\/main)\/([^\s)"']+\.txt)/gi;
    let match;
    while ((match = link.exec(readme)) !== null) {
      const path = decodeURIComponent(match[1]).split("?")[0];
      // Only root standard TXT feeds are universal subscriptions. Export/*
      // contains client-specific JSON/base64 variants and must not be mixed.
      if (!path.includes("/") && pattern.test(path)) listedPaths.add(path);
    }
    if (listedPaths.size) return [...listedPaths];
  } catch {
    // Fall through to a known-good minimal source set.
  }
  return FALLBACK_SOURCES[scope];
}
async function loadSource(path) {
  const url = `${RAW_BASE}${path.split("/").map(encodeURIComponent).join("/")}`;
  const response = await fetch(url, {
    headers: { "user-agent": "universal-subscription-bridge/1.0" },
  });
  if (!response.ok) {
    throw new Error(`${path}: HTTP ${response.status}`);
  }
  return (await response.text())
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => PROXY_URI.test(line));
}
async function buildSubscription(scope) {
  const sources = await discoverSources(scope);
  const results = await Promise.allSettled(sources.map(loadSource));
  const unique = new Set();
  const errors = [];
  for (const result of results) {
    if (result.status === "fulfilled") {
      for (const proxy of result.value) unique.add(proxy);
    } else {
      errors.push(result.reason instanceof Error ? result.reason.message : "unknown source error");
    }
  }
  if (unique.size === 0) {
    throw new Error(`All upstream feeds are unavailable: ${errors.join("; ")}`);
  }
  const generatedAt = new Date().toISOString();
  const lines = [
    `# profile-title: Universal | Igareck ${scope} aggregate`,
    "# profile-update-interval: 60",
    `# Generated: ${generatedAt}; unique proxies: ${unique.size}`,
  ];
  if (errors.length) lines.push(`# Unavailable source(s): ${errors.join("; ")}`);
  const proxyBody = `${[...unique].join("\n")}\n`;
  return {
    body: `${lines.join("\n")}\n${[...unique].join("\n")}\n`,
    plainBody: `${lines.join("\n")}\n${proxyBody}`,
    base64Body: toBase64Utf8(proxyBody),
    count: unique.size,
    errors,
    sources,
  };
}
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405 });
    }
    try {
      const scope = url.searchParams.get("scope") || "all";
      const format = url.searchParams.get("format") || "base64";
      if (format !== "base64" && format !== "plain") {
        return new Response("Unknown format. Use base64 or plain", { status: 400 });
      }
      const subscription = await buildSubscription(scope);
      if (url.pathname === "/status") {
        return Response.json(
          {
            ok: true,
            scope,
            format,
            uniqueProxies: subscription.count,
            failedSources: subscription.errors,
            sources: subscription.sources,
          },
          { headers: { "cache-control": "no-store" } },
        );
      }
      if (url.pathname === "/" || url.pathname === "/subscription") {
        const body = format === "base64" ? subscription.base64Body : subscription.plainBody;
        return new Response(subscription.body, { headers: subscriptionHeaders() });
        return new Response(body, { headers: subscriptionHeaders() });
      }
      return new Response("Not found. Use /subscription or /status", { status: 404 });
    } catch (error) {
      return new Response(`Upstream subscription error: ${error.message}`, { status: 502 });
    }
  },
};
