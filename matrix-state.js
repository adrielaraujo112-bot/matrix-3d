
const HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

const encoder = new TextEncoder();

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: HEADERS
  });
}

function equal(a, b) {
  const x = encoder.encode(String(a ?? ""));
  const y = encoder.encode(String(b ?? ""));
  let diff = x.length ^ y.length;

  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }

  return diff === 0;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sign(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value)
  );

  return base64url(new Uint8Array(signature));
}

async function makeToken(secret) {
  const payload = base64url(
    encoder.encode(JSON.stringify({
      role: "admin",
      exp: Date.now() + 30 * 60 * 1000,
      nonce: crypto.randomUUID()
    }))
  );

  return `${payload}.${await sign(secret, payload)}`;
}

async function validToken(token, secret) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 2) return false;

    const [payload, signature] = parts;

    if (!equal(signature, await sign(secret, payload))) {
      return false;
    }

    const decoded = atob(
      payload.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - payload.length % 4) % 4)
    );

    const data = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(decoded, c => c.charCodeAt(0))
      )
    );

    return data.role === "admin" && data.exp > Date.now();
  } catch {
    return false;
  }
}

function config(env) {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SECRET_KEY;
  const admin = env.MATRIX_ADMIN_TOKEN;

  if (!url || !key || !admin) {
    throw new Error("Configure os três secrets na Cloudflare.");
  }

  return {
    url: url.replace(/\/+$/, ""),
    key,
    admin
  };
}

async function database(env, method, payload) {
  const { url, key } = config(env);

  const result = await fetch(
    `${url}/rest/v1/matrix3d_state?id=eq.global`,
    {
      method,
      headers: {
        apikey: key,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=representation"
      },
      ...(payload ? {
        body: JSON.stringify(payload)
      } : {})
    }
  );

  if (!result.ok) {
    throw new Error(
      `Supabase HTTP ${result.status}: ${(await result.text()).slice(0, 200)}`
    );
  }

  if (method === "GET") {
    const rows = await result.json();
    return rows?.[0]?.payload ?? null;
  }

  return true;
}

export async function onRequest({ request, env }) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: HEADERS
    });
  }

  try {
    const { admin } = config(env);

    if (request.method === "GET") {
      const state = await database(env, "GET");

      return response(state || {
        updatedAt: Date.now(),
        keys: [],
        maintenance: false,
        settings: {
          pixKey: "",
          whatsapp: ""
        },
        accent: {
          color: "#8b5cf6",
          hover: "#a78bfa",
          dark: "#6d28d9"
        }
      });
    }

    if (request.method !== "POST") {
      return response({
        error: "Método não permitido."
      }, 405);
    }

    const body = await request.json();

    if (body.action === "login") {
      if (!equal(body.password, admin)) {
        return response({
          error: "Senha administrativa incorreta."
        }, 401);
      }

      return response({
        token: await makeToken(admin),
        expiresIn: 1800
      });
    }

    const authorization =
      request.headers.get("Authorization") || "";

    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : body.token;

    if (!(await validToken(token, admin))) {
      return response({
        error: "Sessão ADM inválida ou expirada."
      }, 401);
    }

    const p = body.payload;

    if (
      body.action !== "save" ||
      !p ||
      typeof p !== "object" ||
      !Array.isArray(p.keys) ||
      typeof p.maintenance !== "boolean" ||
      !p.settings ||
      !p.accent
    ) {
      return response({
        error: "Estado Matrix 3D inválido."
      }, 400);
    }

    if (p.keys.length > 5000) {
      return response({
        error: "Limite de KEYs excedido."
      }, 413);
    }

    await database(env, "POST", {
      id: "global",
      payload: p,
      updated_at: new Date().toISOString()
    });

    return response({
      ok: true,
      updatedAt: Date.now()
    });

  } catch (error) {
    return response({
      error: error.message || "Erro interno."
    }, 500);
  }
}
