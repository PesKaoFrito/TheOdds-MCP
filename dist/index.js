import http from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const PORT = Number(process.env.PORT || 3000);
const CONFIGURED_PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || process.env.RENDER_EXTERNAL_URL || "").replace(/\/$/, "");
const MCP_OWNER_PASSWORD = process.env.MCP_OWNER_PASSWORD || "";
const THEODDS_API_KEY = process.env.THEODDS_API_KEY || "";
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 8);
const CLIENT_STORE_PATH = process.env.CLIENT_STORE_PATH || join(process.cwd(), ".data", "oauth-clients.json");

const clients = new Map();
const authCodes = new Map();
const tokens = new Map();

const REGION_PRESETS = {
  us: { regions: "us", markets: "h2h", oddsFormat: "american" },
  uk: { regions: "uk", markets: "h2h" },
  eu: { regions: "eu", markets: "h2h" },
  au: { regions: "au", markets: "h2h" }
};

const tools = [
  regionTool("us", "Upcoming head-to-head odds for United States bookmakers, American odds format."),
  regionTool("uk", "Upcoming head-to-head odds for United Kingdom bookmakers."),
  regionTool("eu", "Upcoming head-to-head odds for European bookmakers."),
  regionTool("au", "Upcoming head-to-head odds for Australian bookmakers."),
  {
    name: "theodds_get_sports",
    description: "List sports available from The Odds API.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "theodds_get_upcoming_odds",
    description: "Fetch upcoming odds from The Odds API with configurable region, markets, and odds format.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          enum: ["us", "uk", "eu", "au"],
          description: "Bookmaker region."
        },
        markets: {
          type: "string",
          default: "h2h",
          description: "Comma-separated markets, for example h2h."
        },
        oddsFormat: {
          type: "string",
          enum: ["american", "decimal"],
          description: "Odds format."
        }
      },
      required: ["region"],
      additionalProperties: false
    }
  },
  {
    name: "theodds_get_odds_by_sport",
    description: "Fetch odds for a specific sport key from The Odds API, for example soccer_epl, basketball_nba, americanfootball_nfl, or baseball_mlb.",
    inputSchema: {
      type: "object",
      properties: {
        sportKey: {
          type: "string",
          description: "The Odds API sport key. Use theodds_get_sports to discover valid keys."
        },
        region: {
          type: "string",
          enum: ["us", "uk", "eu", "au"],
          default: "us",
          description: "Bookmaker region."
        },
        markets: {
          type: "string",
          default: "h2h",
          description: "Comma-separated markets, for example h2h."
        },
        oddsFormat: {
          type: "string",
          enum: ["american", "decimal"],
          description: "Odds format."
        }
      },
      required: ["sportKey"],
      additionalProperties: false
    }
  }
];

function regionTool(region, description) {
  return {
    name: `theodds_get_upcoming_odds_${region}`,
    description,
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  };
}

function json(res, status, body, headers = {}) {
  const payload = body === undefined ? "" : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "authorization,content-type,mcp-session-id,accept",
    "access-control-expose-headers": "mcp-session-id,www-authenticate",
    ...headers
  });
  res.end(payload);
}

function text(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "access-control-allow-origin": "*",
    ...headers
  });
  res.end(body);
}

function html(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    ...headers
  });
  res.end(body);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function publicBaseUrl(req) {
  if (CONFIGURED_PUBLIC_BASE_URL) {
    return CONFIGURED_PUBLIC_BASE_URL;
  }

  const protocol = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${PORT}`;
  return `${protocol}://${host}`.replace(/\/$/, "");
}

function oauthMetadata(req) {
  const baseUrl = publicBaseUrl(req);
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "client_credentials"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    code_challenge_methods_supported: ["plain", "S256"],
    scopes_supported: ["mcp"],
    service_documentation: "https://the-odds-api.com/liveapi/guides/v4/"
  };
}

function protectedResourceMetadata(req) {
  const baseUrl = publicBaseUrl(req);
  return {
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://the-odds-api.com/liveapi/guides/v4/"
  };
}

function bearerChallenge(req) {
  return `Bearer resource_metadata="${publicBaseUrl(req)}/.well-known/oauth-protected-resource"`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function parseFormOrJson(req, rawBody) {
  const contentType = req.headers["content-type"] || "";
  if (contentType.includes("application/json")) {
    return rawBody ? JSON.parse(rawBody) : {};
  }

  const params = new URLSearchParams(rawBody);
  return Object.fromEntries(params.entries());
}

function newSecret(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function loadClients() {
  try {
    const storedClients = JSON.parse(readFileSync(CLIENT_STORE_PATH, "utf8"));
    for (const [clientId, client] of Object.entries(storedClients)) {
      clients.set(clientId, client);
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.warn(`Could not load OAuth clients: ${error.message}`);
    }
  }
}

function saveClients() {
  try {
    mkdirSync(dirname(CLIENT_STORE_PATH), { recursive: true });
    writeFileSync(CLIENT_STORE_PATH, JSON.stringify(Object.fromEntries(clients), null, 2));
  } catch (error) {
    console.warn(`Could not save OAuth clients: ${error.message}`);
  }
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function parseBasicClientAuth(req) {
  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Basic\s+(.+)$/i);
  if (!match) {
    return {};
  }

  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator === -1) {
    return {};
  }

  return {
    client_id: decodeURIComponent(decoded.slice(0, separator)),
    client_secret: decodeURIComponent(decoded.slice(separator + 1))
  };
}

function sha256Base64Url(value) {
  return createHash("sha256").update(value).digest("base64url");
}

function issueToken(subject) {
  const accessToken = newSecret();
  const expiresAt = Date.now() + TOKEN_TTL_SECONDS * 1000;
  tokens.set(accessToken, { subject, expiresAt });
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: TOKEN_TTL_SECONDS
  };
}

function isAuthorized(req) {
  if (!MCP_OWNER_PASSWORD) {
    return true;
  }

  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return false;
  }

  const token = tokens.get(match[1]);
  if (!token || token.expiresAt < Date.now()) {
    if (token) tokens.delete(match[1]);
    return false;
  }

  return true;
}

async function theOddsFetch(path, params = {}) {
  if (!THEODDS_API_KEY) {
    throw new Error("Missing THEODDS_API_KEY");
  }

  const url = new URL(`https://api.the-odds-api.com/v4/${path}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  url.searchParams.set("apiKey", THEODDS_API_KEY);

  const response = await fetch(url, {
    headers: {
      accept: "application/json",
      "user-agent": "theodds-mcp/1.0"
    }
  });

  const remaining = response.headers.get("x-requests-remaining");
  const used = response.headers.get("x-requests-used");
  const textBody = await response.text();
  let data;
  try {
    data = textBody ? JSON.parse(textBody) : null;
  } catch {
    data = textBody;
  }

  if (!response.ok) {
    const detail = typeof data === "string" ? data : JSON.stringify(data);
    throw new Error(`The Odds API ${response.status}: ${detail}`);
  }

  return { data, usage: { requestsRemaining: remaining, requestsUsed: used } };
}

async function callTool(name, args = {}) {
  if (name.startsWith("theodds_get_upcoming_odds_")) {
    const region = name.replace("theodds_get_upcoming_odds_", "");
    const preset = REGION_PRESETS[region];
    if (!preset) throw new Error(`Unsupported region preset: ${region}`);
    return theOddsFetch("sports/upcoming/odds/", preset);
  }

  if (name === "theodds_get_sports") {
    return theOddsFetch("sports");
  }

  if (name === "theodds_get_upcoming_odds") {
    const region = args.region;
    if (!REGION_PRESETS[region]) {
      throw new Error("region must be one of: us, uk, eu, au");
    }

    return theOddsFetch("sports/upcoming/odds/", {
      regions: region,
      markets: args.markets || "h2h",
      oddsFormat: args.oddsFormat || (region === "us" ? "american" : undefined)
    });
  }

  if (name === "theodds_get_odds_by_sport") {
    const sportKey = args.sportKey;
    const region = args.region || "us";
    if (!sportKey || typeof sportKey !== "string") {
      throw new Error("sportKey is required. Use theodds_get_sports to discover valid keys.");
    }
    if (!REGION_PRESETS[region]) {
      throw new Error("region must be one of: us, uk, eu, au");
    }

    return theOddsFetch(`sports/${encodeURIComponent(sportKey)}/odds`, {
      regions: region,
      markets: args.markets || "h2h",
      oddsFormat: args.oddsFormat || (region === "us" ? "american" : undefined)
    });
  }

  throw new Error(`Unknown tool: ${name}`);
}

async function handleRpc(request) {
  const method = request.method;
  const id = request.id ?? null;

  try {
    if (method === "initialize") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-03-26",
          capabilities: { tools: {} },
          serverInfo: { name: "theodds-mcp", version: "1.0.0" }
        }
      };
    }

    if (method === "notifications/initialized") {
      return null;
    }

    if (method === "tools/list") {
      return { jsonrpc: "2.0", id, result: { tools } };
    }

    if (method === "tools/call") {
      const toolName = request.params?.name;
      const args = request.params?.arguments || {};
      const result = await callTool(toolName, args);
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2)
            }
          ]
        }
      };
    }

    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${method}` }
    };
  } catch (error) {
    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32000, message: error.message }
    };
  }
}

async function handleMcp(req, res) {
  if (!isAuthorized(req)) {
    json(res, 401, { error: "unauthorized" }, { "www-authenticate": bearerChallenge(req) });
    return;
  }

  if (req.method === "GET") {
    json(res, 200, {
      name: "theodds-mcp",
      version: "1.0.0",
      transport: "streamable-http",
      oauth: MCP_OWNER_PASSWORD ? protectedResourceMetadata(req) : null
    });
    return;
  }

  const rawBody = await readBody(req);
  const payload = rawBody ? JSON.parse(rawBody) : {};
  const requests = Array.isArray(payload) ? payload : [payload];
  const responses = [];

  for (const rpcRequest of requests) {
    const response = await handleRpc(rpcRequest);
    if (response) responses.push(response);
  }

  const sessionId = req.headers["mcp-session-id"] || newSecret(16);
  const body = Array.isArray(payload) ? responses : responses[0] || {};
  json(res, 200, body, { "mcp-session-id": sessionId });
}

async function handleRegister(req, res) {
  const rawBody = await readBody(req);
  const metadata = rawBody ? parseFormOrJson(req, rawBody) : {};
  const clientId = newSecret(18);
  const requestedAuthMethod = metadata.token_endpoint_auth_method || "none";
  const tokenEndpointAuthMethod = ["none", "client_secret_post", "client_secret_basic"].includes(requestedAuthMethod)
    ? requestedAuthMethod
    : "none";
  const clientSecret = tokenEndpointAuthMethod === "none" ? undefined : newSecret(32);
  const redirectUris = Array.isArray(metadata.redirect_uris) ? metadata.redirect_uris : [];
  const grantTypes = Array.isArray(metadata.grant_types) && metadata.grant_types.length
    ? metadata.grant_types
    : ["authorization_code"];
  const responseTypes = Array.isArray(metadata.response_types) && metadata.response_types.length
    ? metadata.response_types
    : ["code"];

  clients.set(clientId, {
    clientSecret,
    tokenEndpointAuthMethod,
    redirectUris,
    grantTypes,
    responseTypes,
    clientName: metadata.client_name || "Dynamic MCP client",
    clientUri: metadata.client_uri,
    scope: metadata.scope || "mcp"
  });
  saveClients();

  const response = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: tokenEndpointAuthMethod,
    redirect_uris: redirectUris,
    grant_types: grantTypes,
    response_types: responseTypes,
    client_name: metadata.client_name || "Dynamic MCP client",
    scope: metadata.scope || "mcp"
  };

  if (metadata.client_uri) response.client_uri = metadata.client_uri;
  if (clientSecret) {
    response.client_secret = clientSecret;
    response.client_secret_expires_at = 0;
  }

  json(res, 201, response, {
    "cache-control": "no-store",
    pragma: "no-cache"
  });
}

function renderAuthorizeForm(res, params, error = "") {
  const hiddenInputs = [...params.entries()]
    .filter(([key]) => key !== "password")
    .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
    .join("\n");

  html(res, error ? 401 : 200, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TheOdds MCP Authorization</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Arial, sans-serif; background: #f6f7f9; color: #101828; }
    main { width: min(420px, calc(100vw - 32px)); background: white; border: 1px solid #d0d5dd; border-radius: 8px; padding: 28px; box-shadow: 0 16px 32px rgba(16, 24, 40, 0.08); }
    h1 { font-size: 22px; margin: 0 0 8px; }
    p { margin: 0 0 18px; color: #475467; line-height: 1.45; }
    label { display: block; font-size: 14px; font-weight: 700; margin-bottom: 8px; }
    input[type="password"] { width: 100%; box-sizing: border-box; border: 1px solid #98a2b3; border-radius: 6px; padding: 12px; font-size: 16px; }
    button { width: 100%; margin-top: 16px; border: 0; border-radius: 6px; padding: 12px 14px; background: #155eef; color: white; font-size: 16px; font-weight: 700; cursor: pointer; }
    .error { margin-bottom: 16px; color: #b42318; font-weight: 700; }
  </style>
</head>
<body>
  <main>
    <h1>TheOdds MCP</h1>
    <p>Enter the owner password to authorize ChatGPT.</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <form method="post" action="/oauth/authorize">
      ${hiddenInputs}
      <label for="password">Owner password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Authorize</button>
    </form>
  </main>
</body>
</html>`);
}

function issueAuthorizationCode(res, params) {
  const responseType = params.get("response_type");
  const clientId = params.get("client_id") || "";
  const redirectUri = params.get("redirect_uri");
  const state = params.get("state");
  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method") || "plain";
  let client = clients.get(clientId);
  const code = newSecret(24);

  if (responseType !== "code") {
    json(res, 400, { error: "unsupported_response_type" });
    return;
  }

  if (!client) {
    client = {
      clientSecret: undefined,
      tokenEndpointAuthMethod: "none",
      redirectUris: redirectUri ? [redirectUri] : [],
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
      clientName: "Recovered public MCP client",
      scope: params.get("scope") || "mcp"
    };
    clients.set(clientId, client);
    saveClients();
  }

  if (!redirectUri) {
    json(res, 400, { error: "invalid_request", error_description: "Missing redirect_uri" });
    return;
  }

  if (client.redirectUris.length && !client.redirectUris.includes(redirectUri)) {
    json(res, 400, { error: "invalid_request", error_description: "redirect_uri is not registered for this client" });
    return;
  }

  if (codeChallengeMethod !== "plain" && codeChallengeMethod !== "S256") {
    json(res, 400, { error: "invalid_request", error_description: "Unsupported code_challenge_method" });
    return;
  }

  authCodes.set(code, {
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod,
    scope: params.get("scope") || client.scope,
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  res.writeHead(302, { location: redirect.toString() });
  res.end();
}

async function handleAuthorize(req, res, url) {
  if (!MCP_OWNER_PASSWORD) {
    issueAuthorizationCode(res, url.searchParams);
    return;
  }

  if (req.method === "GET") {
    renderAuthorizeForm(res, url.searchParams);
    return;
  }

  const rawBody = await readBody(req);
  const params = new URLSearchParams(rawBody);
  const password = params.get("password") || "";
  if (!safeEqual(MCP_OWNER_PASSWORD, password)) {
    renderAuthorizeForm(res, params, "Invalid password.");
    return;
  }

  params.delete("password");
  issueAuthorizationCode(res, params);
}

async function handleToken(req, res) {
  const rawBody = await readBody(req);
  const body = parseFormOrJson(req, rawBody);
  const basicAuth = parseBasicClientAuth(req);
  if (!body.client_id && basicAuth.client_id) body.client_id = basicAuth.client_id;
  if (!body.client_secret && basicAuth.client_secret) body.client_secret = basicAuth.client_secret;
  const grantType = body.grant_type;

  if (grantType === "authorization_code") {
    const code = authCodes.get(body.code);
    if (!code || code.expiresAt < Date.now()) {
      json(res, 400, { error: "invalid_grant" });
      return;
    }

    let client = clients.get(code.clientId);
    if (!client) {
      client = {
        clientSecret: undefined,
        tokenEndpointAuthMethod: "none",
        redirectUris: code.redirectUri ? [code.redirectUri] : [],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        clientName: "Recovered public MCP client",
        scope: code.scope || "mcp"
      };
      clients.set(code.clientId, client);
      saveClients();
    }

    if (body.client_id && body.client_id !== code.clientId) {
      json(res, 401, { error: "invalid_client" });
      return;
    }

    if (code.redirectUri && body.redirect_uri && body.redirect_uri !== code.redirectUri) {
      json(res, 400, { error: "invalid_grant" });
      return;
    }

    if (client.tokenEndpointAuthMethod !== "none" && !safeEqual(client.clientSecret, body.client_secret || "")) {
      json(res, 401, { error: "invalid_client" });
      return;
    }

    if (code.codeChallenge) {
      if (!body.code_verifier) {
        json(res, 400, { error: "invalid_request", error_description: "Missing code_verifier" });
        return;
      }

      const verifierChallenge = code.codeChallengeMethod === "S256"
        ? sha256Base64Url(body.code_verifier)
        : body.code_verifier;
      if (!safeEqual(verifierChallenge, code.codeChallenge)) {
        json(res, 400, { error: "invalid_grant" });
        return;
      }
    }

    authCodes.delete(body.code);
    json(res, 200, issueToken(code.clientId));
    return;
  }

  if (grantType === "client_credentials") {
    const client = clients.get(body.client_id);
    const validRegisteredClient = client && safeEqual(client.clientSecret, body.client_secret || "");
    const validOwnerSecret = MCP_OWNER_PASSWORD && safeEqual(MCP_OWNER_PASSWORD, body.client_secret || body.password || "");

    if (!validRegisteredClient && !validOwnerSecret) {
      json(res, 401, { error: "invalid_client" });
      return;
    }

    json(res, 200, issueToken(body.client_id || "owner"));
    return;
  }

  json(res, 400, { error: "unsupported_grant_type" });
}

async function router(req, res) {
  const url = new URL(req.url || "/", publicBaseUrl(req));

  if (req.method === "OPTIONS") {
    json(res, 204);
    return;
  }

  try {
    if (url.pathname === "/health") {
      json(res, 200, { ok: true });
    } else if (url.pathname === "/.well-known/oauth-authorization-server" || url.pathname.startsWith("/.well-known/oauth-authorization-server/")) {
      json(res, 200, oauthMetadata(req));
    } else if (url.pathname === "/.well-known/oauth-protected-resource" || url.pathname.startsWith("/.well-known/oauth-protected-resource/")) {
      json(res, 200, protectedResourceMetadata(req));
    } else if ((url.pathname === "/oauth/register" || url.pathname === "/register" || url.pathname === "/oauth/clients") && req.method === "POST") {
      await handleRegister(req, res);
    } else if (url.pathname === "/oauth/authorize" && (req.method === "GET" || req.method === "POST")) {
      await handleAuthorize(req, res, url);
    } else if (url.pathname === "/oauth/token" && req.method === "POST") {
      await handleToken(req, res);
    } else if (url.pathname === "/mcp" && (req.method === "GET" || req.method === "POST")) {
      await handleMcp(req, res);
    } else {
      text(res, 404, "Not found");
    }
  } catch (error) {
    json(res, 500, { error: "server_error", error_description: error.message });
  }
}

const server = http.createServer(router);

loadClients();

server.listen(PORT, () => {
  console.log(`TheOdds MCP listening on ${CONFIGURED_PUBLIC_BASE_URL || `http://localhost:${PORT}`}`);
});
