
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/ahorros") {
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
            mensaje: "Error al consultar D1"
          },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
