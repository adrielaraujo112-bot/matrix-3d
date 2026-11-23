
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

const enc = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

function equalText(a, b) {
  const x = enc.encode(String(a ?? ""));
  const y = enc.encode(String(b ?? ""));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sign(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  return b64(new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(value))
  ));
}

async function createToken(secret) {
  const payload = b64(enc.encode(JSON.stringify({
    role: "admin",
    exp: Date.now() + 1800000,
    nonce: crypto.randomUUID()
  })));
  return payload + "." + await sign(secret, payload);
}

async function validToken(token, secret) {
  try {
    const [payload, signature, extra] = String(token || "").split(".");
    if (!payload || !signature || extra !== undefined) return false;
    if (!equalText(signature, await sign(secret, payload))) return false;

    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
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

  const response = await fetch(
    `${url}/rest/v1/matrix3d_state?id=eq.global`,
    {
      method,
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=representation"
      },
      ...(payload ? { body: JSON.stringify(payload) } : {})
    }
  );

  if (!response.ok) {
    throw new Error(`Supabase HTTP ${response.status}`);
  }

  if (method === "GET") {
    const rows = await response.json();
    return rows?.[0]?.payload ?? null;
  }

  return true;
}

export async function onRequest({ request, env }) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: JSON_HEADERS
    });
  }

  try {
    const { admin } = config(env);

    if (request.method === "GET") {
      const state = await database(env, "GET");
      return json(state || {
        updatedAt: Date.now(),
        keys: [],
        maintenance: false,
        settings: { pixKey: "", whatsapp: "" },
        accent: {
          color: "#8b5cf6",
          hover: "#a78bfa",
          dark: "#6d28d9"
        }
      });
    }

    if (request.method !== "POST") {
      return json({ error: "Método não permitido." }, 405);
    }

    const body = await request.json();

    if (body.action === "login") {
      if (!equalText(body.password, admin)) {
        return json({ error: "Senha administrativa incorreta." }, 401);
      }

      return json({
        token: await createToken(admin),
        expiresIn: 1800
      });
    }

    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ")
      ? auth.slice(7)
      : body.token;

    if (!(await validToken(token, admin))) {
      return json({ error: "Sessão ADM inválida ou expirada." }, 401);
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
      return json({ error: "Estado Matrix 3D inválido." }, 400);
    }

    if (p.keys.length > 5000) {
      return json({ error: "Limite de KEYs excedido." }, 413);
    }

    await database(env, "POST", {
      id: "global",
      payload: p,
      updated_at: new Date().toISOString()
    });

    return json({ ok: true, updatedAt: Date.now() });

  } catch (error) {
    return json({
      error: error.message || "Erro interno."
    }, 500);
  }
                                         }
        
