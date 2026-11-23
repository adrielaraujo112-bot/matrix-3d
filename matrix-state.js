const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function equalText(a, b) {
  const left = encoder.encode(String(a ?? ""));
  const right = encoder.encode(String(b ?? ""));
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

async function makeToken(secret) {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const payload = toBase64Url(encoder.encode(JSON.stringify({
    role: "admin",
    exp: Date.now() + 30 * 60 * 1000,
    nonce: toBase64Url(nonce),
  })));
  const signature = toBase64Url(await hmac(secret, payload));
  return `${payload}.${signature}`;
}

async function validToken(token, secret) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) return false;

    const expected = toBase64Url(await hmac(secret, parts[0]));
    if (!equalText(parts[1], expected)) return false;

    const payload = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
    return payload.role === "admin" &&
      Number.isFinite(payload.exp) &&
      payload.exp > Date.now();
  } catch {
    return false;
  }
}

function config(env) {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SECRET_KEY;
  const admin = env.MATRIX_ADMIN_TOKEN;

  if (!url || !key || !admin) {
    throw new Error(
      "Configure SUPABASE_URL, SUPABASE_SECRET_KEY e MATRIX_ADMIN_TOKEN em Settings > Variables and Secrets."
    );
  }

  return { url: String(url).replace(/\/+$/, ""), key, admin };
}

async function db(env, method, payload) {
  const { url, key } = config(env);
  const response = await fetch(
    `${url}/rest/v1/matrix3d_state?id=eq.global`,
    {
      method,
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=representation",
      },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
    }
  );

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 180);
    throw new Error(`Supabase HTTP ${response.status}: ${detail}`);
  }

  if (method === "GET") {
    const rows = await response.json();
    return rows?.[0]?.payload ?? null;
  }

  return true;
}

function defaultState() {
  return {
    updatedAt: Date.now(),
    keys: [],
    maintenance: false,
    settings: { pixKey: "", whatsapp: "" },
    accent: { color: "#8b5cf6", hover: "#a78bfa", dark: "#6d28d9" },
  };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: JSON_HEADERS });
  }

  try {
    const { admin } = config(env);

    if (request.method === "GET") {
      const state = await db(env, "GET");
      return json(state || defaultState());
    }

    if (request.method !== "POST") {
      return json({ error: "Método não permitido." }, 405);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "JSON inválido." }, 400);
    }

    if (body?.action === "login") {
      if (!equalText(body.password || "", admin)) {
        return json({ error: "Senha administrativa incorreta." }, 401);
      }
      return json({ token: await makeToken(admin), expiresIn: 1800 });
    }

    const authorization = request.headers.get("Authorization") || "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : body?.token;

    if (!(await validToken(token, admin))) {
      return json({ error: "Sessão ADM inválida ou expirada." }, 401);
    }

    const payload = body?.payload;
    if (
      body?.action !== "save" ||
      !payload ||
      typeof payload !== "object" ||
      !Array.isArray(payload.keys) ||
      typeof payload.maintenance !== "boolean" ||
      !payload.settings ||
      !payload.accent
    ) {
      return json({ error: "Estado Matrix 3D inválido." }, 400);
    }

    if (payload.keys.length > 5000) {
      return json({ error: "Limite de KEYs excedido." }, 413);
    }

    await db(env, "POST", {
      id: "global",
      payload,
      updated_at: new Date().toISOString(),
    });

    return json({ ok: true, updatedAt: Date.now() });
  } catch (error) {
    // Avoid returning internal stack traces or secret values to visitors.
    return json({ error: error?.message || "Erro interno." }, 500);
  }
}
