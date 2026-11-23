
const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

function response(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function equal(a, b) {
  a = String(a);
  b = String(b);

  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return base64url(new Uint8Array(signature));
}

async function makeToken(secret) {
  const data = {
    role: "admin",
    exp: Date.now() + 30 * 60 * 1000,
    nonce: crypto.randomUUID()
  };

  const payload = base64url(
    new TextEncoder().encode(JSON.stringify(data))
  );

  return `${payload}.${await sign(payload, secret)}`;
}

async function validToken(token, secret) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 2) return false;

    const [payload, signature] = parts;
    const expected = await sign(payload, secret);

    if (!equal(signature, expected)) return false;

    const data = JSON.parse(
      new TextDecoder().decode(decodeBase64url(payload))
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
    throw new Error("Configure as três variáveis secretas na Cloudflare.");
  }

  return {
    url: url.replace(/\/$/, ""),
    key,
    admin
  };
}

async function database(env, method, payload) {
  const { url, key } = config(env);

  const endpoint = `${url}/rest/v1/matrix3d_state`;

  const target = method === "GET"
    ? `${endpoint}?id=eq.global&select=payload`
    : `${endpoint}?on_conflict=id`;

  const result = await fetch(target, {
    method,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=representation"
    },
    ...(payload ? { body: JSON.stringify(payload) } : {})
  });

  if (!result.ok) {
    throw new Error(`Erro no Supabase: HTTP ${result.status}`);
  }

  if (method === "GET") {
    const rows = await result.json();
    return rows?.[0]?.payload ?? null;
  }

  return true;
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  try {
    const { admin } = config(env);

    if (request.method === "GET") {
      const state = await database(env, "GET");

      return response(200, state || {
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
      return response(405, { error: "Método não permitido." });
    }

    const body = await request.json();

    if (body.action === "login") {
      if (!equal(body.password || "", admin)) {
        return response(401, {
          error: "Senha administrativa incorreta."
        });
      }

      return response(200, {
        token: await makeToken(admin),
        expiresIn: 1800
      });
    }

    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ")
      ? auth.slice(7)
      : body.token;

    if (!await validToken(token, admin)) {
      return response(401, {
        error: "Sessão ADM inválida ou expirada."
      });
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
      return response(400, {
        error: "Estado Matrix 3D inválido."
      });
    }

    if (p.keys.length > 5000) {
      return response(413, {
        error: "Limite de KEYS excedido."
      });
    }

    await database(env, "POST", {
      id: "global",
      payload: p,
      updated_at: new Date().toISOString()
    });

    return response(200, {
      ok: true,
      updatedAt: Date.now()
    });

  } catch (error) {
    return response(500, {
      error: error.message || "Erro interno."
    });
  }
    }
