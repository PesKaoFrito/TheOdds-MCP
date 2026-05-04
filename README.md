# TheOdds MCP

Servidor MCP HTTP con OAuth para consumir The Odds API.

## Configuracion local

```powershell
$env:THEODDS_API_KEY="tu-api-key"
$env:MCP_OWNER_PASSWORD="un-secreto-largo"
$env:PUBLIC_BASE_URL="http://localhost:3000"
npm start
```

`THEODDS_API_KEY` es obligatoria. No se deja la llave hardcodeada para que el repo pueda subirse a Render sin exponer secretos.

## Deploy en Render

Este repo incluye `render.yaml` para Blueprint.

1. Sube el proyecto a GitHub.
2. En Render, crea un Blueprint desde el repo.
3. Configura estas variables:

- `THEODDS_API_KEY`: tu llave de The Odds API.
- `PUBLIC_BASE_URL`: la URL publica del servicio, por ejemplo `https://theodds-mcp.onrender.com`.
- `MCP_OWNER_PASSWORD`: Render puede generarla automaticamente desde `render.yaml`, o puedes definir una propia.

Render usa:

- Build command: `npm install`
- Start command: `npm start`
- Health check: `/health`

El endpoint para conectar el MCP sera:

```text
https://TU-SERVICIO.onrender.com/mcp
```

## Endpoints

- `POST /mcp`: endpoint MCP JSON-RPC.
- `GET /.well-known/oauth-authorization-server`: metadata OAuth.
- `GET /.well-known/oauth-protected-resource`: metadata de recurso protegido.
- `POST /oauth/register`: registro dinamico simple.
- `GET /oauth/authorize`: autorizacion OAuth con redireccion.
- `POST /oauth/token`: emision de token.

El registro dinamico acepta `application/json` compatible con RFC 7591. Para clientes publicos como ChatGPT, usa `token_endpoint_auth_method: "none"` y Authorization Code con PKCE.

## Herramientas MCP

- `theodds_get_upcoming_odds_us`
- `theodds_get_upcoming_odds_uk`
- `theodds_get_upcoming_odds_eu`
- `theodds_get_upcoming_odds_au`
- `theodds_get_sports`
- `theodds_get_upcoming_odds`

`theodds_get_upcoming_odds` permite elegir `region`, `markets` y `oddsFormat`.
