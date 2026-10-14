
const Ahorros = (() => {
  const dinero = centavos =>
    new Intl.NumberFormat("es-MX", {
      style: "currency",
      currency: "MXN"
    }).format(centavos / 100);

  async function api(ruta, opciones = {}) {
    const respuesta = await fetch(ruta, {
      credentials: "same-origin",
      ...opciones,
      headers: {
        "Content-Type": "application/json",
        ...opciones.headers
      }
    });

    const datos = await respuesta.json();

    if (!respuesta.ok) {
      throw new Error(datos.mensaje || "No se pudo completar la solicitud");
    }

    return datos;
  }

  async function cargar() {
    const datos = await api("/api/ahorros");

    document.querySelector("#ahorro-total").textContent =
      dinero(datos.total_centavos);
    document.querySelector("#ahorro-meta").textContent =
      dinero(datos.meta_centavos);
    document.querySelector("#ahorro-persona1").textContent =
      dinero(datos.persona1_centavos);
    document.querySelector("#ahorro-persona2").textContent =
      dinero(datos.persona2_centavos);

    const historial = document.querySelector("#ahorro-historial");
    historial.replaceChildren();

    for (const aporte of datos.historial) {
      const fila = document.createElement("li");
      fila.textContent =
        `${aporte.contribution_date} · ` +
        `${aporte.member === "persona1" ? "Persona 1" : "Persona 2"} · ` +
        `${dinero(aporte.amount_cents)}` +
        (aporte.note ? ` · ${aporte.note}` : "");
      historial.appendChild(fila);
    }
  }

  async function iniciar() {
    const mensaje = document.querySelector("#ahorro-mensaje");

    try {
      await cargar();
      mensaje.textContent = "Ahorros actualizados.";
    } catch (error) {
      mensaje.textContent = error.message;
    }

    document.querySelector("#form-aportacion")
      ?.addEventListener("submit", async evento => {
        evento.preventDefault();
        const formulario = evento.currentTarget;
        const boton = formulario.querySelector("button");

        try {
          boton.disabled = true;

          const cantidad = Number(
            formulario.elements.cantidad.value
          );

          if (!Number.isFinite(cantidad) || cantidad <= 0) {
            throw new Error("Escribe una cantidad válida.");
          }

          await api("/api/ahorros/aportaciones", {
            method: "POST",
            body: JSON.stringify({
              amount_cents: Math.round(cantidad * 100),
              contribution_date: formulario.elements.fecha.value,
              note: formulario.elements.nota.value
            })
          });

          formulario.reset();
          mensaje.textContent = "¡Aportación guardada! 💗";
          await cargar();
        } catch (error) {
          mensaje.textContent = error.message;
        } finally {
          boton.disabled = false;
        }
      });

    document.querySelector("#form-meta")
      ?.addEventListener("submit", async evento => {
        evento.preventDefault();
        const formulario = evento.currentTarget;
        const boton = formulario.querySelector("button");

        try {
          boton.disabled = true;

          const cantidad = Number(formulario.elements.meta.value);

          if (!Number.isFinite(cantidad) || cantidad < 0) {
            throw new Error("Escribe una meta válida.");
          }

          await api("/api/ahorros/meta", {
            method: "PUT",
            body: JSON.stringify({
              goal_cents: Math.round(cantidad * 100)
            })
          });

          mensaje.textContent = "¡Meta actualizada! 🌱";
          await cargar();
        } catch (error) {
          mensaje.textContent = error.message;
        } finally {
          boton.disabled = false;
        }
      });
  }

  return { iniciar, cargar };
})();

document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector("#seccion-ahorros")) {
    Ahorros.iniciar();
  }
});
