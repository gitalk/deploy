// ../../../proxy-core/src/pkcs8.ts
var RSA_ALGORITHM_IDENTIFIER = new Uint8Array([
  48,
  13,
  6,
  9,
  42,
  134,
  72,
  134,
  247,
  13,
  1,
  1,
  1,
  5,
  0
]);
function der(tag, content) {
  const lengthBytes = [];
  if (content.length < 128) {
    lengthBytes.push(content.length);
  } else {
    const big = [];
    for (let n = content.length; n > 0; n = Math.floor(n / 256)) big.unshift(n % 256);
    lengthBytes.push(128 | big.length, ...big);
  }
  const out = new Uint8Array(1 + lengthBytes.length + content.length);
  out[0] = tag;
  out.set(lengthBytes, 1);
  out.set(content, 1 + lengthBytes.length);
  return out;
}
function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function readTlv(bytes, offset) {
  const tag = bytes[offset];
  if (tag === void 0) return null;
  let cursor = offset + 1;
  let length = bytes[cursor];
  if (length === void 0) return null;
  cursor += 1;
  if (length & 128) {
    const count = length & 127;
    length = 0;
    for (let i = 0; i < count; i++) {
      const byte = bytes[cursor];
      if (byte === void 0) return null;
      length = length * 256 + byte;
      cursor += 1;
    }
  }
  if (cursor + length > bytes.length) return null;
  return { tag, start: cursor, end: cursor + length, next: cursor + length };
}
function isPkcs1(bytes) {
  const outer = readTlv(bytes, 0);
  if (!outer || outer.tag !== 48) return false;
  const version = readTlv(bytes, outer.start);
  if (!version || version.tag !== 2) return false;
  if (version.end - version.start !== 1 || bytes[version.start] !== 0) return false;
  return bytes[version.next] === 2;
}
function pkcs1ToPkcs8(pkcs1) {
  const version = new Uint8Array([2, 1, 0]);
  return der(48, concat(version, RSA_ALGORITHM_IDENTIFIER, der(4, pkcs1)));
}
function pemToPkcs8(pem) {
  const body = pem.replace(/\\n/g, "\n").replace(/\r/g, "").replace(/-----BEGIN (RSA )?PRIVATE KEY-----/, "").replace(/-----END (RSA )?PRIVATE KEY-----/, "").replace(/\s+/g, "");
  const bytes = Uint8Array.from(atob(body), (char) => char.charCodeAt(0));
  return isPkcs1(bytes) ? pkcs1ToPkcs8(bytes) : bytes;
}

// ../../../proxy-core/src/index.ts
var GITHUB_API = "https://api.github.com";
var GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize";
var GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
var GITHUB_USER_AGENT = "gitalk-proxy";
var TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1e3;
var SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
var REPO_VISIBILITY_TTL_MS = 5 * 60 * 1e3;
var REPO_CACHE_LIMIT = 500;
var ANONYMOUS_BODY_LIMIT = 16 * 1024;
var CURSOR_LIMIT = 4096;
var ANONYMOUS_READ_QUERIES = {
  gitalkDiscussion: `
query gitalkDiscussion($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    discussion(number: $number) {
      id
      number
      title
      url
      locked
    }
  }
}`,
  gitalkDiscussionList: `
query gitalkDiscussionList($owner: String!, $repo: String!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $repo) {
    discussions(first: $first, after: $after, orderBy: {field: CREATED_AT, direction: DESC}) {
      nodes {
        id
        number
        title
        url
        locked
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}`,
  gitalkDiscussionComments: `
query gitalkDiscussionComments($owner: String!, $repo: String!, $number: Int!, $first: Int, $last: Int, $after: String, $before: String) {
  repository(owner: $owner, name: $repo) {
    discussion(number: $number) {
      comments(first: $first, last: $last, after: $after, before: $before) {
        totalCount
        pageInfo {
          hasNextPage
          hasPreviousPage
          startCursor
          endCursor
        }
        nodes {
          id
          databaseId
          author { login avatarUrl url ... on User { name } }
          createdAt
          url
          bodyHTML
          reactionGroups { content viewerHasReacted reactors(first: 0) { totalCount } }
          replies(first: 100) {
            totalCount
            nodes {
              id
              databaseId
              author { login avatarUrl url ... on User { name } }
              createdAt
              url
              bodyHTML
              reactionGroups { content viewerHasReacted reactors(first: 0) { totalCount } }
            }
          }
        }
      }
    }
  }
}`,
  gitalkIssue: `
query gitalkIssue($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      id
      number
      title
      url
      locked
    }
  }
}`,
  gitalkIssueByLabel: `
query gitalkIssueByLabel($owner: String!, $repo: String!, $labels: [String!]!) {
  repository(owner: $owner, name: $repo) {
    issues(first: 1, labels: $labels, states: [OPEN, CLOSED]) {
      nodes {
        id
        number
        title
        url
        locked
      }
    }
  }
}`,
  gitalkIssueComments: `
query gitalkIssueComments($owner: String!, $repo: String!, $number: Int!, $first: Int, $last: Int, $after: String, $before: String) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      comments(first: $first, last: $last, after: $after, before: $before) {
        totalCount
        pageInfo {
          hasNextPage
          hasPreviousPage
          startCursor
          endCursor
        }
        nodes {
          id
          databaseId
          author { login avatarUrl url ... on User { name } }
          createdAt
          url
          bodyHTML
          reactionGroups { content viewerHasReacted reactors(first: 0) { totalCount } }
        }
      }
    }
  }
}`
};
var installationTokenCache = /* @__PURE__ */ new Map();
var repoVisibilityCache = /* @__PURE__ */ new Map();
var json = (body, init = {}) => new Response(JSON.stringify(body), {
  ...init,
  headers: { "Content-Type": "application/json", ...init.headers }
});
async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");
  const cors = corsHeaders(origin, env.GITALK_ALLOWED_ORIGINS);
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        ...cors,
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        // Echo whatever the browser says it wants to send.
        //
        // A fixed list here is a bug generator: every header the client adds
        // later fails the preflight for exactly the requests carrying it, while
        // requests carrying none of them keep working. Authorization,
        // X-GitHub-Api-Version and X-Github-Next-Global-ID each broke a
        // different feature this way. The origin allow list is the real access
        // control; which headers may accompany an allowed origin is not a
        // boundary worth maintaining by hand.
        "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") ?? "Accept, Authorization, Content-Type, If-None-Match, X-GitHub-Api-Version, X-Github-Next-Global-ID",
        "Access-Control-Expose-Headers": "ETag, Cache-Control, Last-Modified, Expires",
        "Access-Control-Max-Age": "86400"
      }
    });
  }
  try {
    switch (url.pathname) {
      case "/":
        return json({ ok: true, service: "gitalk-proxy" }, { headers: cors });
      case "/oauth/authorize":
        return handleAuthorize(url, env);
      case "/oauth/callback":
        return await handleCallback(url, env, cors);
      case "/oauth/token":
        return await handleTokenExchange(request, env, cors);
      case "/graphql":
        return await handleGraphql(request, env, ctx, cors);
      default:
        return json({ error: "Not found" }, { status: 404, headers: cors });
    }
  } catch (err) {
    console.error("proxy error:", err);
    return json({ error: "Proxy request failed" }, { status: 502, headers: cors });
  }
}
function handleAuthorize(url, env) {
  const returnTo = safeReturnTo(
    url.searchParams.get("return_to"),
    url.origin,
    env.GITALK_ALLOWED_ORIGINS
  );
  const target = new URL(GITHUB_AUTHORIZE);
  target.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  target.searchParams.set("redirect_uri", `${url.origin}/oauth/callback`);
  target.searchParams.set("state", safeEncode(returnTo));
  return Response.redirect(target.toString(), 302);
}
async function handleCallback(url, env, cors) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  const returnTo = state ? safeReturnTo(safeDecode(state), url.origin, env.GITALK_ALLOWED_ORIGINS) : "/";
  if (error) return redirectBack(returnTo, { error }, url.origin);
  if (!code) return json({ error: "`code` is required" }, { status: 400, headers: cors });
  const tokens = await exchangeCode(env, code);
  if (!tokens) return redirectBack(returnTo, { error: "token_exchange_failed" }, url.origin);
  const session = await sealSession(env, toSessionPayload(tokens));
  return redirectBack(returnTo, { gitalk_session: session }, url.origin);
}
async function handleTokenExchange(request, env, cors) {
  let session = "";
  try {
    const body2 = await request.json();
    session = body2.session ?? "";
  } catch {
    return json({ error: "Invalid JSON body" }, { status: 400, headers: cors });
  }
  const payload = await openSession(env, session);
  if (!payload) return json({ error: "Invalid or expired session" }, { status: 401, headers: cors });
  const current = await renewIfExpired(env, payload);
  if (!current) {
    return json({ error: "Session expired; sign in again" }, { status: 401, headers: cors });
  }
  const body = {
    access_token: current.payload.accessToken
  };
  if (current.renewed) {
    body.session = await sealSession(env, current.payload);
    if (current.payload.expiresAt) {
      body.expires_in = Math.max(0, Math.round((current.payload.expiresAt - Date.now()) / 1e3));
    }
  }
  return json(body, { headers: cors });
}
async function handleGraphql(request, env, ctx, cors) {
  const body = await request.text();
  const token = bearerFrom(request);
  if (token) {
    return forwardGraphql(request, body, token, cors);
  }
  const anonymous = await authorizeAnonymousRead(body, env);
  if (!anonymous.ok) {
    return json({ error: anonymous.error }, { status: anonymous.status, headers: cors });
  }
  return forwardGraphql(
    request,
    JSON.stringify({ query: anonymous.query, variables: anonymous.variables }),
    anonymous.token,
    cors
  );
}
async function authorizeAnonymousRead(body, env) {
  if (body.length > ANONYMOUS_BODY_LIMIT) {
    return deny(413, "Request body is too large");
  }
  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return deny(400, "Invalid JSON body");
  }
  if (typeof payload.query !== "string") return deny(401, "`query` is required");
  const operation = parseOperation(payload.query);
  if (!operation || operation.type !== "query" || !operation.name) {
    return deny(401, "Anonymous reads require an allowlisted read query");
  }
  const canonical = ANONYMOUS_READ_QUERIES[operation.name];
  if (!canonical) {
    return deny(401, "Anonymous reads require an allowlisted read query");
  }
  if (!isPlainObject(payload.variables)) return deny(400, "`variables` must be an object");
  const owner = payload.variables.owner;
  const repo = payload.variables.repo;
  if (!isRepoPart(owner) || !isRepoPart(repo)) {
    return deny(400, "`variables.owner` and `variables.repo` must be repository names");
  }
  if (!validReadVariables(operation.name, payload.variables)) {
    return deny(400, "Invalid variables for this read operation");
  }
  const token = await installationToken(env);
  if (!token) return deny(503, "Anonymous reads are unavailable");
  if (!await isPublicRepository(owner, repo, token)) {
    return deny(403, "Anonymous reads are only available for public repositories");
  }
  return { ok: true, token, query: canonical, variables: payload.variables };
}
var deny = (status, error) => ({ ok: false, status, error });
function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function isRepoPart(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 100 && value !== "." && value !== ".." && /^[A-Za-z0-9_.-]+$/.test(value);
}
function isPositiveInt(value) {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 2147483647;
}
function isPageSize(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 100;
}
function isCursor(value) {
  return typeof value === "string" && value.length > 0 && value.length <= CURSOR_LIMIT;
}
function validReadVariables(operation, variables) {
  switch (operation) {
    case "gitalkDiscussion":
    case "gitalkIssue":
      return isPositiveInt(variables.number);
    case "gitalkDiscussionList":
      return isPageSize(variables.first) && (variables.after == null || isCursor(variables.after));
    case "gitalkIssueByLabel": {
      const labels = variables.labels;
      return Array.isArray(labels) && labels.length > 0 && labels.length <= 10 && labels.every((label) => typeof label === "string" && label.length > 0 && label.length <= 200);
    }
    case "gitalkDiscussionComments":
    case "gitalkIssueComments": {
      if (!isPositiveInt(variables.number)) return false;
      const hasFirst = variables.first != null;
      const hasLast = variables.last != null;
      if (hasFirst === hasLast) return false;
      if (hasFirst && !isPageSize(variables.first)) return false;
      if (hasLast && !isPageSize(variables.last)) return false;
      if (variables.after != null && !isCursor(variables.after)) return false;
      if (variables.before != null && !isCursor(variables.before)) return false;
      if (hasFirst && variables.before != null) return false;
      if (hasLast && variables.after != null) return false;
      return true;
    }
    default:
      return false;
  }
}
function parseOperation(document) {
  const tokens = tokenizeGraphql(document);
  if (!tokens || !tokens.length) return null;
  const first = tokens[0];
  let type;
  let index = 1;
  let name = null;
  if (first === "{") {
    type = "query";
    index = 0;
  } else if (first === "query" || first === "mutation" || first === "subscription") {
    type = first;
  } else {
    return null;
  }
  if (first !== "{") {
    if (isNameToken(tokens[index])) {
      name = tokens[index];
      index++;
    }
    if (tokens[index] === "(") {
      index = skipBalanced(tokens, index, "(", ")");
      if (index < 0) return null;
    }
    while (tokens[index] === "@") {
      index++;
      if (!isNameToken(tokens[index])) return null;
      index++;
      if (tokens[index] === "(") {
        index = skipBalanced(tokens, index, "(", ")");
        if (index < 0) return null;
      }
    }
  }
  if (tokens[index] !== "{") return null;
  index = skipBalanced(tokens, index, "{", "}");
  if (index < 0 || index !== tokens.length) return null;
  return { type, name };
}
function isNameToken(token) {
  return typeof token === "string" && /^[_A-Za-z][_0-9A-Za-z]*$/.test(token);
}
function tokenizeGraphql(document) {
  const tokens = [];
  let index = 0;
  while (index < document.length) {
    const char = document[index];
    if (char === " " || char === "	" || char === "\n" || char === "\r" || char === "," || char === "\uFEFF") {
      index++;
      continue;
    }
    if (char === "#") {
      while (index < document.length && document[index] !== "\n") index++;
      continue;
    }
    if (char === '"') {
      const triple = document.slice(index, index + 3) === '"""';
      index += triple ? 3 : 1;
      while (index < document.length) {
        if (triple) {
          if (document.slice(index, index + 3) === '"""') {
            index += 3;
            break;
          }
          index++;
        } else {
          if (document[index] === "\\") {
            index += 2;
            continue;
          }
          if (document[index] === '"') {
            index++;
            break;
          }
          index++;
        }
      }
      if (index > document.length) return null;
      tokens.push("STRING");
      continue;
    }
    if (/[_A-Za-z]/.test(char)) {
      const start = index;
      while (index < document.length && /[_0-9A-Za-z]/.test(document[index])) index++;
      tokens.push(document.slice(start, index));
      continue;
    }
    if (/[0-9]/.test(char)) {
      while (index < document.length && /[0-9.eE+-]/.test(document[index])) index++;
      tokens.push("NUMBER");
      continue;
    }
    if (document.slice(index, index + 3) === "...") {
      tokens.push("...");
      index += 3;
      continue;
    }
    tokens.push(char);
    index++;
  }
  return tokens;
}
function skipBalanced(tokens, start, open, close) {
  let depth = 0;
  for (let index = start; index < tokens.length; index++) {
    if (tokens[index] === open) depth++;
    else if (tokens[index] === close) {
      depth--;
      if (depth === 0) return index + 1;
    }
  }
  return -1;
}
async function forwardGraphql(request, body, token, cors) {
  const nextGlobalId = request.headers.get("X-Github-Next-Global-ID");
  const ifNoneMatch = request.headers.get("If-None-Match");
  const upstream = await fetch(`${GITHUB_API}/graphql`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      ...nextGlobalId ? { "X-Github-Next-Global-ID": nextGlobalId } : {},
      ...ifNoneMatch ? { "If-None-Match": ifNoneMatch } : {},
      "User-Agent": GITHUB_USER_AGENT
    },
    body
  });
  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json");
  headers.set("Access-Control-Expose-Headers", "ETag, Cache-Control, Last-Modified, Expires");
  for (const name of ["ETag", "Cache-Control", "Last-Modified", "Expires"]) {
    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }
  const upstreamVary = upstream.headers.get("Vary");
  if (upstreamVary) {
    const merged = /* @__PURE__ */ new Set(["Origin", ...upstreamVary.split(",").map((v) => v.trim())]);
    headers.set("Vary", [...merged].filter(Boolean).join(", "));
  }
  return new Response(upstream.status === 304 ? null : await upstream.text(), {
    status: upstream.status,
    headers
  });
}
function bearerFrom(request) {
  const header = request.headers.get("Authorization");
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}
async function requestToken(env, body) {
  const response = await fetch(GITHUB_TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": GITHUB_USER_AGENT
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      ...body
    })
  });
  const payload = await response.json();
  if (payload.error || !payload.access_token) {
    console.error("token request failed:", payload.error ?? response.status);
    return null;
  }
  return toTokenSet(payload);
}
var exchangeCode = (env, code) => requestToken(env, { code });
var refreshAccessToken = (env, refreshToken) => requestToken(env, { grant_type: "refresh_token", refresh_token: refreshToken });
function toTokenSet(payload) {
  const now = Date.now();
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt: payload.expires_in ? now + payload.expires_in * 1e3 : void 0,
    refreshTokenExpiresAt: payload.refresh_token_expires_in ? now + payload.refresh_token_expires_in * 1e3 : void 0
  };
}
function toSessionPayload(tokens) {
  return {
    accessToken: tokens.accessToken,
    issuedAt: Date.now(),
    refreshToken: tokens.refreshToken,
    expiresAt: tokens.expiresAt,
    refreshTokenExpiresAt: tokens.refreshTokenExpiresAt
  };
}
async function renewIfExpired(env, payload) {
  const expiring = payload.expiresAt !== void 0;
  if (!expiring || payload.expiresAt - TOKEN_REFRESH_MARGIN_MS > Date.now()) {
    return { payload, renewed: false };
  }
  if (!payload.refreshToken) {
    console.error("access token expired and no refresh token was issued");
    return null;
  }
  if (payload.refreshTokenExpiresAt && payload.refreshTokenExpiresAt <= Date.now()) {
    console.error("refresh token expired");
    return null;
  }
  const refreshed = await refreshAccessToken(env, payload.refreshToken);
  if (!refreshed) return null;
  return {
    payload: toSessionPayload({
      ...refreshed,
      refreshToken: refreshed.refreshToken ?? payload.refreshToken
    }),
    renewed: true
  };
}
async function installationToken(env) {
  const cacheKey = `${env.GITHUB_APP_ID}
${env.GITHUB_INSTALLATION_ID ?? ""}`;
  const cached = installationTokenCache.get(cacheKey);
  if (cached && cached.expiresAt - Date.now() > TOKEN_REFRESH_MARGIN_MS) {
    return cached.token;
  }
  const installationId = await resolveInstallationId(env);
  if (!installationId) {
    console.error("no installation found for this app");
    return null;
  }
  const jwt = await signAppJwt(env);
  const response = await fetch(
    `${GITHUB_API}/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "User-Agent": GITHUB_USER_AGENT
      }
    }
  );
  if (!response.ok) {
    console.error("installation token request failed:", response.status);
    return null;
  }
  const data = await response.json();
  if (!data.token) return null;
  installationTokenCache.set(cacheKey, {
    token: data.token,
    expiresAt: new Date(data.expires_at ?? Date.now() + 60 * 60 * 1e3).getTime()
  });
  return data.token;
}
async function isPublicRepository(owner, repo, token) {
  const cacheKey = `${owner.toLowerCase()}/${repo.toLowerCase()}`;
  const cached = repoVisibilityCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.isPublic;
  let isPublic = false;
  try {
    const response = await fetch(
      `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "User-Agent": GITHUB_USER_AGENT
        }
      }
    );
    if (response.ok) {
      const data = await response.json();
      isPublic = data.private === false && (data.visibility === void 0 || data.visibility === "public");
    }
  } catch {
    return false;
  }
  if (repoVisibilityCache.size >= REPO_CACHE_LIMIT) {
    const oldest = repoVisibilityCache.keys().next().value;
    if (oldest !== void 0) repoVisibilityCache.delete(oldest);
  }
  repoVisibilityCache.set(cacheKey, {
    isPublic,
    expiresAt: Date.now() + REPO_VISIBILITY_TTL_MS
  });
  return isPublic;
}
async function resolveInstallationId(env) {
  if (env.GITHUB_INSTALLATION_ID) return Number(env.GITHUB_INSTALLATION_ID);
  const jwt = await signAppJwt(env);
  const response = await fetch(`${GITHUB_API}/app/installations?per_page=1`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
      "User-Agent": GITHUB_USER_AGENT
    }
  });
  if (!response.ok) {
    console.error("installation lookup failed:", response.status);
    return null;
  }
  const list = await response.json();
  return list[0]?.id ?? null;
}
async function signAppJwt(env) {
  const key = await importPemKey(env.GITHUB_APP_PRIVATE_KEY);
  const now = Math.floor(Date.now() / 1e3);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64Url(
    JSON.stringify({
      iat: now - 30,
      // clock drift tolerance
      exp: now + 600,
      // GitHub rejects anything over 10 minutes
      iss: env.GITHUB_APP_ID
    })
  );
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(`${header}.${claims}`)
  );
  return `${header}.${claims}.${base64UrlBytes(new Uint8Array(signature))}`;
}
async function importPemKey(pem) {
  const binary = pemToPkcs8(pem);
  return crypto.subtle.importKey(
    "pkcs8",
    binary.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}
function base64Url(input) {
  return base64UrlBytes(new TextEncoder().encode(input));
}
function base64UrlBytes(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sealSession(env, payload) {
  const key = await sessionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return `${base64UrlBytes(iv)}.${base64UrlBytes(new Uint8Array(cipher))}`;
}
async function openSession(env, sealed) {
  const [ivPart, dataPart] = sealed.split(".");
  if (!ivPart || !dataPart) return null;
  try {
    const key = await sessionKey(env);
    const iv = fromBase64Url(ivPart);
    const data = fromBase64Url(dataPart);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer },
      key,
      data.buffer
    );
    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    if (Date.now() - payload.issuedAt > SESSION_TTL_SECONDS * 1e3) return null;
    return payload;
  } catch {
    return null;
  }
}
async function sessionKey(env) {
  const raw = hexToBytes(env.SESSION_ENCRYPTION_KEY);
  return crypto.subtle.importKey(
    "raw",
    raw.buffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}
function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
function allowedOriginList(allowed) {
  return (allowed ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}
function corsHeaders(origin, allowed) {
  const list = allowedOriginList(allowed);
  const permit = !list.length || list.includes("*") || origin && list.includes(origin) ? origin ?? "*" : list[0];
  return { "Access-Control-Allow-Origin": permit, Vary: "Origin" };
}
function safeReturnTo(value, origin, allowed) {
  try {
    const target = new URL(value ?? "/", origin);
    const path = `${target.pathname.replace(/^\/+/, "/")}${target.search}${target.hash}`;
    if (target.origin === origin) return path;
    if (allowedOriginList(allowed).includes(target.origin)) {
      return `${target.origin}${path}`;
    }
    return "/";
  } catch {
    return "/";
  }
}
function redirectBack(returnTo, params, origin) {
  const target = new URL(returnTo, origin);
  for (const [k, v] of Object.entries(params)) target.searchParams.set(k, v);
  return Response.redirect(target.toString(), 302);
}
function safeEncode(value) {
  return btoa(encodeURIComponent(value)).replace(/=+$/, "");
}
function safeDecode(value) {
  try {
    return decodeURIComponent(atob(value));
  } catch {
    return "/";
  }
}

// ../../../proxy-worker/src/index.ts
var index_default = {
  fetch: handle
};
export {
  index_default as default
};
