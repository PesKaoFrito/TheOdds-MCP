import http from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 3000);
const CONFIGURED_PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || process.env.RENDER_EXTERNAL_URL || "").replace(/\/$/, "");
const MCP_OWNER_PASSWORD = process.env.MCP_OWNER_PASSWORD || "";
const THEODDS_API_KEY = process.env.THEODDS_API_KEY || "";
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 8);

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
    code_challenge_methods_supported: ["plain", "S256"]
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

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
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
  const clientSecret = newSecret(32);
  clients.set(clientId, {
    clientSecret,
    redirectUris: metadata.redirect_uris || metadata.redirectUris || []
  });
  json(res, 201, {
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: "client_secret_post"
  });
}

function handleAuthorize(req, res, url) {
  const clientId = url.searchParams.get("client_id") || "anonymous";
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const code = newSecret(24);

  if (!redirectUri) {
    json(res, 400, { error: "invalid_request", error_description: "Missing redirect_uri" });
    return;
  }

  authCodes.set(code, {
    clientId,
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  res.writeHead(302, { location: redirect.toString() });
  res.end();
}

async function handleToken(req, res) {
  const rawBody = await readBody(req);
  const body = parseFormOrJson(req, rawBody);
  const grantType = body.grant_type;

  if (grantType === "authorization_code") {
    const code = authCodes.get(body.code);
    if (!code || code.expiresAt < Date.now()) {
      json(res, 400, { error: "invalid_grant" });
      return;
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
    } else if (url.pathname === "/.well-known/oauth-authorization-server") {
      json(res, 200, oauthMetadata(req));
    } else if (url.pathname === "/.well-known/oauth-protected-resource") {
      json(res, 200, protectedResourceMetadata(req));
    } else if (url.pathname === "/oauth/register" && req.method === "POST") {
      await handleRegister(req, res);
    } else if (url.pathname === "/oauth/authorize" && req.method === "GET") {
      handleAuthorize(req, res, url);
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

server.listen(PORT, () => {
  console.log(`TheOdds MCP listening on ${CONFIGURED_PUBLIC_BASE_URL || `http://localhost:${PORT}`}`);
});
