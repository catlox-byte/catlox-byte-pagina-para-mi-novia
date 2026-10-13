
export async function onRequestGet({ env }) {
  try {
    const result = await env.AHORROS_DB
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all();

    return Response.json({
      ok: true,
      mensaje: "Conexión con D1 exitosa",
      tablas: result.results
    });
  } catch (error) {
    return Response.json(
      {
        ok: false,
        mensaje: "No se pudo conectar con la base de datos"
      },
      { status: 500 }
    );
  }
}
