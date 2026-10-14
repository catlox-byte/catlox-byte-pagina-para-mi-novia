
const SESSION_MINUTES = 60;
const MAX_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store", ...headers }
  });
}

function hex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(bytes = 32) {
  return hex(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return hex(digest);
}

async function hashPin(pin, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pin),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 310000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return hex(bits);
}

function cookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const part = header.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  return part ? part.slice(name.length + 1) : null;
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return origin === new URL(request.url).origin;
}

async function sessionMember(request, env) {
  const token = cookie(request, "ahorro_session");
  if (!token) return null;

  const tokenHash = await sha256(token);

  const session = await env.AHORROS_DB.prepare(`
    SELECT member, expires_at
    FROM savings_sessions
    WHERE token_hash = ?
  `).bind(tokenHash).first();

  if (!session || Date.parse(session.expires_at) <= Date.now()) {
    if (session) {
      await env.AHORROS_DB.prepare(
        "DELETE FROM savings_sessions WHERE token_hash = ?"
      ).bind(tokenHash).run();
    }
    return null;
  }

  return session.member;
}

async function handle(request, env) {
  const url = new URL(request.url);
  const db = env.AHORROS_DB;
  const path = url.pathname;

  // Las solicitudes que modifican datos deben venir del mismo origen.
  if (path.startsWith("/api/") &&
      request.method !== "GET" &&
      !sameOrigin(request)) {
    return json({ ok: false, mensaje: "Origen no permitido" }, 403);
  }

  // Registro inicial: requiere secreto y solo funciona si no hay usuarios.
  if (path === "/api/setup" && request.method === "POST") {
    if (!env.SETUP_SECRET) {
      return json({
        ok: false,
        mensaje: "Configuración inicial deshabilitada"
      }, 403);
    }

    if (request.headers.get("Authorization") !==
        `Bearer ${env.SETUP_SECRET}`) {
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
        mensaje: "Usa dos PIN distintos de cuatro dígitos"
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

    const salt1 = randomHex(16);
    const salt2 = randomHex(16);

    const stored1 = `${salt1}:${await hashPin(pins.persona1, salt1)}`;
    const stored2 = `${salt2}:${await hashPin(pins.persona2, salt2)}`;

    try {
      await db.batch([
        db.prepare(
          "INSERT INTO savings_users (member, pin_hash) VALUES (?, ?)"
        ).bind("persona1", stored1),
        db.prepare(
          "INSERT INTO savings_users (member, pin_hash) VALUES (?, ?)"
        ).bind("persona2", stored2)
      ]);
    } catch {
      return json({
        ok: false,
        mensaje: "No se pudo completar el registro. Comprueba si ya existen usuarios."
      }, 409);
    }

    return json({
      ok: true,
      mensaje: "Usuarios registrados"
    }, 201);
  }

  // Inicio de sesión.
  if (path === "/api/login" && request.method === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const now = new Date();

    let lock = await db.prepare(`
      SELECT attempts, locked_until
      FROM login_limits
      WHERE ip = ?
    `).bind(ip).first();

    if (lock?.locked_until) {
      const lockTime = Date.parse(lock.locked_until);

      if (Number.isFinite(lockTime) && lockTime > now.getTime()) {
        return json({
          ok: false,
          mensaje: "Demasiados intentos. Espera antes de volver a probar."
        }, 429);
      }

      // Reiniciar el contador cuando termina el bloqueo.
      await db.prepare(
        "DELETE FROM login_limits WHERE ip = ?"
      ).bind(ip).run();

      lock = null;
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, mensaje: "Solicitud inválida" }, 400);
    }

    const { member, pin } = body || {};

    if (!["persona1", "persona2"].includes(member) ||
        typeof pin !== "string" ||
        !/^\d{4}$/.test(pin)) {
      return json({ ok: false, mensaje: "Datos inválidos" }, 400);
    }

    const user = await db.prepare(`
      SELECT pin_hash
      FROM savings_users
      WHERE member = ?
    `).bind(member).first();

    let valid = false;

    if (user) {
      const [salt, stored] = user.pin_hash.split(":");

      if (salt && stored) {
        valid = (await hashPin(pin, salt)) === stored;
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

      return json({
        ok: false,
        mensaje: attempts >= MAX_ATTEMPTS
          ? "Demasiados intentos. Espera 15 minutos."
          : "PIN incorrecto"
      }, 401);
    }

    await db.prepare(
      "DELETE FROM login_limits WHERE ip = ?"
    ).bind(ip).run();

    const token = randomHex();
    const tokenHash = await sha256(token);
    const expires = new Date(
      Date.now() + SESSION_MINUTES * 60000
    ).toISOString();

    await db.prepare(`
      INSERT INTO savings_sessions (member, token_hash, expires_at)
      VALUES (?, ?, ?)
    `).bind(member, tokenHash, expires).run();

    return json(
      {
        ok: true,
        member,
        expires_in_minutes: SESSION_MINUTES
      },
      200,
      {
        "Set-Cookie":
          `ahorro_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MINUTES * 60}`
      }
    );
  }

  // Cierre de sesión.
  if (path === "/api/logout" && request.method === "POST") {
    const token = cookie(request, "ahorro_session");

    if (token) {
      await db.prepare(
        "DELETE FROM savings_sessions WHERE token_hash = ?"
      ).bind(await sha256(token)).run();
    }

    return json(
      { ok: true },
      200,
      {
        "Set-Cookie":
          "ahorro_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
      }
    );
  }

  // Consulta protegida del ahorro.
  
  // Registrar una aportación para la cuenta autenticada.
  if (path === "/api/ahorros/aportaciones" &&
      request.method === "POST") {

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, mensaje: "Solicitud inválida" }, 400);
    }

    const { amount_cents, contribution_date, note = "" } = body || {};

    if (!Number.isSafeInteger(amount_cents) ||
        amount_cents <= 0 ||
        amount_cents > 100000000) {
      return json({
        ok: false,
        mensaje: "El importe debe ser positivo y válido"
      }, 400);
    }

    if (typeof contribution_date !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(contribution_date) ||
        new Date(contribution_date + "T00:00:00Z")
          .toISOString().slice(0, 10) !== contribution_date) {
      return json({ ok: false, mensaje: "Fecha inválida" }, 400);
    }

    if (typeof note !== "string" || note.length > 200) {
      return json({
        ok: false,
        mensaje: "La nota no puede superar 200 caracteres"
      }, 400);
    }

    const result = await db.prepare(`
      INSERT INTO contributions
        (member, amount_cents, contribution_date, note)
      VALUES (?, ?, ?, ?)
    `).bind(
      member,
      amount_cents,
      contribution_date,
      note.trim() || null
    ).run();

    return json({
      ok: true,
      id: result.meta.last_row_id,
      mensaje: "Aportación registrada"
    }, 201);
  }

  // Actualizar la meta compartida.
  if (path === "/api/ahorros/meta" &&
      request.method === "PUT") {

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, mensaje: "Solicitud inválida" }, 400);
    }

    const {
  member,
  amount_cents,
  contribution_date,
  note = ""
} = body || {};

if (!["persona1", "persona2"].includes(member)) {
  return json({
    ok: false,
    mensaje: "Selecciona una persona válida"
  }, 400);
}
    if (!Number.isSafeInteger(goal_cents) ||
        goal_cents < 0 ||
        goal_cents > 100000000000) {
      return json({
        ok: false,
        mensaje: "La meta debe ser una cantidad válida en centavos"
      }, 400);
    }

    await db.prepare(`
      UPDATE savings_settings
      SET goal_cents = ?
      WHERE id = 1
    `).bind(goal_cents).run();

    return json({
      ok: true,
      meta_centavos: goal_cents,
      mensaje: "Meta actualizada"
    });
  }

  if (path === "/api/ahorros") {
    if (request.method !== "GET") {
      return json({ ok: false, mensaje: "Método no permitido" }, 405);
    }

    const member = await sessionMember(request, env);

    if (!member) {
      return json({
        ok: false,
        mensaje: "Inicia sesión para continuar"
      }, 401);
    }

    const configuracion = await db.prepare(`
      SELECT goal_cents
      FROM savings_settings
      WHERE id = 1
    `).first();

    const resumen = await db.prepare(`
      SELECT
        COALESCE(SUM(amount_cents), 0) AS total_cents,
        COALESCE(SUM(
          CASE WHEN member = 'persona1'
          THEN amount_cents ELSE 0 END
        ), 0) AS persona1_cents,
        COALESCE(SUM(
          CASE WHEN member = 'persona2'
          THEN amount_cents ELSE 0 END
        ), 0) AS persona2_cents
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
    });
  }

  // Los demás recursos los sirve el sitio estático.
  if (path.startsWith("/api/")) {
    return json({ ok: false, mensaje: "Ruta no disponible" }, 404);
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
     
if (!env.AHORROS_DB) {
  return json({
    ok: false,
    mensaje: "Falta configurar la base de datos"
  }, 500);
}


      return await handle(request, env);
    } catch (error) {
      console.error("Error interno en la API");
      return json({
        ok: false,
        mensaje: "Error interno del servidor"
      }, 500);
    }
  }
};
