"""Graficas de la Fase 5 para el informe (PNG, fondo claro, pensadas para imprimir).

Cuatro figuras, las que pide el ROADMAP:

1. `asr_by_vector.png`: ASR por vector, sin defensas, modelo principal (una serie).
2. `asr_by_model.png`: ASR por vector y modelo, sin defensas (hasta tres series).
3. `asr_by_defense.png`: ASR con cada configuracion de defensas, y el ASR sin bloqueo
   al lado (dos series: cuanto manipula el ataque vs cuanto llega al equipo).
4. `accuracy_vs_latency.png`: costo de cada configuracion en limpios: F1 de IoCs
   contra latencia p50 por reporte (una serie, etiquetas directas).

Convenciones: como maximo tres series por figura, con los tres primeros colores de la
paleta categorica de referencia (validados para daltonismo en cualquier combinacion);
barras finas con valor escrito encima; ejes y rejilla discretos; un solo eje Y.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

#: Paleta categorica de referencia, slots 1-3 (azul, naranja, aguamarina).
SERIES = ("#2a78d6", "#eb6834", "#1baf7a")
SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_MUTED = "#52514e"
GRID = "#e4e3df"


def _setup():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "axes.edgecolor": GRID,
            "axes.labelcolor": TEXT_MUTED,
            "axes.titlecolor": TEXT,
            "axes.titlesize": 12,
            "axes.titleweight": "bold",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "xtick.color": TEXT_MUTED,
            "ytick.color": TEXT_MUTED,
            "font.size": 9,
            "legend.frameon": False,
        }
    )
    return plt


def _percent_axis(ax, ymax: float = 1.0) -> None:
    ax.set_ylim(0, max(ymax, 0.05) * 1.15)
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def grouped_bars(
    path: Path,
    *,
    title: str,
    categories: Sequence[str],
    series: dict[str, Sequence[float | None]],
    subtitle: str = "",
    ylabel: str = "ASR",
) -> Path:
    """Barras agrupadas (1 a 3 series) con el valor escrito sobre cada barra."""
    if not 1 <= len(series) <= len(SERIES):
        raise ValueError(f"entre 1 y {len(SERIES)} series por figura; llegaron {len(series)}")
    plt = _setup()
    width_per_group = 0.8
    bar = width_per_group / len(series)
    fig, ax = plt.subplots(figsize=(max(6.0, 1.1 * len(categories) * max(1, len(series) / 1.5)), 3.8))
    peak = 0.0
    for index, (name, values) in enumerate(series.items()):
        xs = [i - width_per_group / 2 + bar * (index + 0.5) for i in range(len(categories))]
        heights = [v if v is not None else 0.0 for v in values]
        peak = max(peak, *heights) if heights else peak
        bars = ax.bar(xs, heights, width=bar - 0.04, color=SERIES[index], label=name, edgecolor=SURFACE, linewidth=1)
        for rect, value in zip(bars, values):
            label = "s/d" if value is None else f"{value:.0%}"
            ax.annotate(label, (rect.get_x() + rect.get_width() / 2, rect.get_height()),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom",
                        fontsize=8, color=TEXT_MUTED)
    ax.set_xticks(range(len(categories)), categories)
    ax.set_ylabel(ylabel)
    _percent_axis(ax, peak)
    ax.set_title(title, loc="left", pad=22 if len(series) > 1 else 6)
    if subtitle:
        fig.text(0.01, 0.005, subtitle, fontsize=7.5, color=TEXT_MUTED, ha="left", va="bottom")
    if len(series) > 1:
        # Fuera del area de datos, a la derecha del titulo: nunca tapa una etiqueta.
        ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncols=len(series), borderaxespad=0.2)
    fig.tight_layout(rect=(0, 0.04 if subtitle else 0, 1, 1))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path


def accuracy_vs_latency(
    path: Path,
    *,
    points: Sequence[tuple[str, float, float]],
    title: str,
    subtitle: str = "",
    xlabel: str = "Latencia p50 por reporte (s)",
    ylabel: str = "F1 de IoCs en limpios",
) -> Path:
    """Dispersión etiquetada: (nombre, latencia, exactitud) por configuración."""
    plt = _setup()
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    xs = [p[1] for p in points]
    ys = [p[2] for p in points]
    ax.scatter(xs, ys, s=64, color=SERIES[0], edgecolors=SURFACE, linewidths=2, zorder=3)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    # Ejes ajustados a los datos (en una dispersion la posicion, no la longitud, lleva
    # el valor): las configuraciones suelen caer en pocos segundos y centesimas de F1.
    if xs:
        span_x = max(max(xs) - min(xs), 5.0)
        ax.set_xlim(min(xs) - 0.15 * span_x, max(xs) + 0.45 * span_x)
        span_y = max(max(ys) - min(ys), 0.05)
        ax.set_ylim(max(0.0, min(ys) - 0.35 * span_y), min(1.0, max(ys) + 0.35 * span_y))
    ax.set_title(title, loc="left")
    if subtitle:
        fig.text(0.01, 0.005, subtitle, fontsize=7.5, color=TEXT_MUTED, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.04 if subtitle else 0, 1, 1))

    # Etiquetas directas, colocadas despues del layout final. Las configuraciones que
    # caen en el mismo punto comparten etiqueta ("a = b"); cada etiqueta va en la primera
    # de cuatro posiciones que no pise a otra: arriba-der., abajo-der., arriba-izq., abajo-izq.
    merged: dict[tuple[float, float], list[str]] = {}
    for name, x, y in points:
        merged.setdefault((round(x, 0), round(y, 2)), []).append(name)
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    placed = []
    candidates = [((7, 6), "left"), ((7, -13), "left"), ((-7, 6), "right"), ((-7, -13), "right")]
    for (x, y), names in sorted(merged.items()):
        label = " = ".join(names)
        for offset, ha in candidates:
            text = ax.annotate(label, (x, y), xytext=offset, textcoords="offset points",
                               fontsize=8, color=TEXT, ha=ha)
            text.draw(renderer)  # calcula la posicion real antes de medir la caja
            box = text.get_window_extent(renderer).expanded(1.05, 1.15)
            point = ax.transData.transform((x, y))
            if any(other.contains(*point) for other in placed):
                text.remove()
                continue
            if not any(box.overlaps(other) for other in placed):
                placed.append(box)
                break
            text.remove()
        else:  # sin hueco libre: primera posicion
            text = ax.annotate(label, (x, y), xytext=candidates[0][0], textcoords="offset points",
                               fontsize=8, color=TEXT)
            text.draw(renderer)
            placed.append(text.get_window_extent(renderer))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path
