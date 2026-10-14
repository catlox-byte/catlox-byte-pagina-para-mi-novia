
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/ahorros") {
      try {
        // 1. Consultar la meta de ahorro
        const configuracion = await env.AHORROS_DB
          .prepare(
            "SELECT goal_cents FROM savings_settings WHERE id = 1"
          )
          .first();

        // 2. Calcular cuánto se ha ahorrado
        const resumen = await env.AHORROS_DB
          .prepare(`
            SELECT
              COALESCE(SUM(amount_cents), 0) AS total_cents,
              COALESCE(SUM(CASE WHEN member = 'persona1'
                THEN amount_cents ELSE 0 END), 0) AS persona1_cents,
              COALESCE(SUM(CASE WHEN member = 'persona2'
                THEN amount_cents ELSE 0 END), 0) AS persona2_cents
            FROM contributions
          `)
          .first();

        // 3. Consultar las últimas 20 aportaciones
        const historial = await env.AHORROS_DB
          .prepare(`
            SELECT id, member, amount_cents, contribution_date, note
            FROM contributions
            ORDER BY contribution_date DESC, id DESC
            LIMIT 20
          `)
          .all();

        // 4. Enviar los resultados
        return Response.json({
          ok: true,
          meta_centavos: configuracion?.goal_cents ?? 0,
          total_centavos: resumen.total_cents,
          persona1_centavos: resumen.persona1_cents,
          persona2_centavos: resumen.persona2_cents,
          historial: historial.results
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            mensaje: "Error al consultar los ahorros"
          },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
