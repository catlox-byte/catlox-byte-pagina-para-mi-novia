
const SESSION_MINUTES = 60;
const MAX_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers });
}

function hex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hash(value, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(value),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 310000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return hex(bits);
}

function randomHex(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return hex(data);
}

function cookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const part = header.split(";").map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : null;
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}

async function sessionMember(request, env) {
  const token = cookie(request, "ahorro_session");
  if (!token) return null;

  const tokenHash = await hash(token, env.SESSION_SECRET);

  const session = await env.AHORROS_DB.prepare(`
    SELECT member
    FROM savings_sessions
    WHERE token_hash = ?
      AND expires_at > datetime('now')
  `).bind(tokenHash).first();

  return session?.member ?? null;
}

async function handle(request, env) {
  
  if (url.pathname === "/api/setup" && request.method === "POST") {
    if (!env.SETUP_SECRET) {
      return json({ ok: false, mensaje: "Configuración inicial deshabilitada" }, 403);
    }

    const authorization = request.headers.get("Authorization");
    if (authorization !== `Bearer ${env.SETUP_SECRET}`) {
      return json({ ok: false, mensaje: "No autorizado" }, 401);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, mensaje: "Solicitud inválida" }, 400);
    }

    const pins = body?.pins;
    if (!pins ||
        typeof pins.persona1 !== "string" ||
        typeof pins.persona2 !== "string" ||
        !/^\d{4}$/.test(pins.persona1) ||
        !/^\d{4}$/.test(pins.persona2) ||
        pins.persona1 === pins.persona2) {
      return json({
        ok: false,
        mensaje: "Se necesitan dos PIN distintos de cuatro dígitos"
      }, 400);
    }

    const existing = await db.prepare(
      "SELECT COUNT(*) AS total FROM savings_users"
    ).first();

    if (existing.total > 0) {
      return json({
        ok: false,
        mensaje: "El registro inicial ya se utilizó"
      }, 409);
    }

    const salt1 = randomHex();
    const salt2 = randomHex();
    const hash1 = `${salt1}:${await hash(pins.persona1, salt1)}`;
    const hash2 = `${salt2}:${await hash(pins.persona2, salt2)}`;

    await db.batch([
      db.prepare(
        "INSERT INTO savings_users (member, pin_hash) VALUES (?, ?)"
      ).bind("persona1", hash1),
      db.prepare(
        "INSERT INTO savings_users (member, pin_hash) VALUES (?, ?)"
      ).bind("persona2", hash2)
    ]);

    return json({ ok: true, mensaje: "Usuarios registrados" }, 201, {
      "Cache-Control": "no-store"
    });
  }

  const url = new URL(request.url);
  const db = env.AHORROS_DB;

  if (url.pathname.startsWith("/api/")) {
    if (request.method !== "GET" && !sameOrigin(request)) {
      return json({ ok: false, mensaje: "Origen no permitido" }, 403);
    }
  }

  if (url.pathname === "/api/login" && request.method === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const now = new Date().toISOString();
    const lock = await db.prepare(`
      SELECT attempts, locked_until
      FROM login_limits
      WHERE ip = ?
    `).bind(ip).first();

    if (lock?.locked_until && lock.locked_until > now) {
      return json({ ok: false, mensaje: "Demasiados intentos. Espera antes de probar de nuevo." }, 429);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, mensaje: "Solicitud inválida" }, 400);
    }

    const { member, pin } = body || {};
    if (!["persona1", "persona2"].includes(member) ||
        typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
      return json({ ok: false, mensaje: "Datos inválidos" }, 400);
    }

    const user = await db.prepare(`
      SELECT pin_hash FROM savings_users WHERE member = ?
    `).bind(member).first();

    let valid = false;
    if (user) {
      const [salt, stored] = user.pin_hash.split(":");
      if (salt && stored) {
        valid = (await hash(pin, salt)) === stored;
      }
    }

    if (!valid) {
      const attempts = (lock?.attempts || 0) + 1;
      const lockedUntil = attempts >= MAX_ATTEMPTS
        ? new Date(Date.now() + LOCK_MINUTES * 60000).toISOString()
        : null;

      await db.prepare(`
        INSERT INTO login_limits (ip, attempts, locked_until)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
          attempts = excluded.attempts,
          locked_until = excluded.locked_until
      `).bind(ip, attempts, lockedUntil).run();

      return json({ ok: false, mensaje: "PIN incorrecto" }, 401);
    }

    await db.prepare("DELETE FROM login_limits WHERE ip = ?")
      .bind(ip).run();

    const token = randomHex();
    const tokenHash = await hash(token, env.SESSION_SECRET);
    const expires = new Date(Date.now() + SESSION_MINUTES * 60000)
      .toISOString();

    await db.prepare(`
      INSERT INTO savings_sessions (member, token_hash, expires_at)
      VALUES (?, ?, ?)
    `).bind(member, tokenHash, expires).run();

    return json(
      { ok: true, member, expires_in_minutes: SESSION_MINUTES },
      200,
      {
        "Set-Cookie": `ahorro_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MINUTES * 60}`,
        "Cache-Control": "no-store"
      }
    );
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const token = cookie(request, "ahorro_session");
    if (token) {
      await db.prepare("DELETE FROM savings_sessions WHERE token_hash = ?")
        .bind(await hash(token, env.SESSION_SECRET)).run();
    }

    return json(
      { ok: true },
      200,
      {
        "Set-Cookie": "ahorro_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
        "Cache-Control": "no-store"
      }
    );
  }

  if (url.pathname.startsWith("/api/ahorros")) {
    const member = await sessionMember(request, env);
    if (!member) {
      return json({ ok: false, mensaje: "Inicia sesión para continuar" }, 401);
    }

    if (url.pathname === "/api/ahorros" && request.method === "GET") {
      const configuracion = await db.prepare(
        "SELECT goal_cents FROM savings_settings WHERE id = 1"
      ).first();

      const resumen = await db.prepare(`
        SELECT
          COALESCE(SUM(amount_cents), 0) AS total_cents,
          COALESCE(SUM(CASE WHEN member = 'persona1'
            THEN amount_cents ELSE 0 END), 0) AS persona1_cents,
          COALESCE(SUM(CASE WHEN member = 'persona2'
            THEN amount_cents ELSE 0 END), 0) AS persona2_cents
        FROM contributions
      `).first();

      const historial = await db.prepare(`
        SELECT id, member, amount_cents, contribution_date, note
        FROM contributions
        ORDER BY contribution_date DESC, id DESC
        LIMIT 20
      `).all();

      return json({
        ok: true,
        meta_centavos: configuracion?.goal_cents ?? 0,
        total_centavos: resumen.total_cents,
        persona1_centavos: resumen.persona1_cents,
        persona2_centavos: resumen.persona2_cents,
        historial: historial.results
      }, 200, { "Cache-Control": "no-store" });
    }

    return json({ ok: false, mensaje: "Ruta no disponible todavía" }, 404);
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
      if (!env.AHORROS_DB || !env.SESSION_SECRET) {
        return json({ ok: false, mensaje: "Falta configurar el servidor" }, 500);
      }
      return await handle(request, env);
    } catch (error) {
      console.error("Error interno en la API");
      return json({ ok: false, mensaje: "Error interno del servidor" }, 500);
    }
  }
};
