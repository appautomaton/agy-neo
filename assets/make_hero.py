#!/usr/bin/env python3
"""Draw assets/hero.svg: agy's running line as the patched binary draws it, animated for the README.

The motion is the binary's own: the star's 24 breath frames at the spinner's 100 ms, and the band's
swing across the verb, column by column, as RunningLightWindow places it (Site #49l). Both read their
constants from patch_agy.py, so the picture follows the patch. Stars are paths, not glyphs: a reader's
fonts may lack `✦`. Run from anywhere: `python3 assets/make_hero.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import patch_agy as P  # noqa: E402

FONT = "ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"
SIZE, CH, ROW = 14, 8.43, 22          # font size, column width, row height (px)
PAD_X, PAD_Y = 28, 30
# Sampled from the patched CLI in Ghostty: background, user bar, text, rules, faint text.
BG, EDGE, FG = "#000000", "#2a2a2a", "#c8c8c8"
FAINT, ASIDE, RULE, BAR = "#646464", "#999999", "#535353", "#3a3a3a"
# statusline.sh's powerline: dark ink on pastel blocks, each closed by a chevron in its own color.
INK = "#11111b"
# (icon, label, color): the icons are its Nerd Font marks, drawn as paths, since a reader may lack the font.
POWERLINE = ((None, "accept-edits", "#b0e1a2"), (None, "gemini-4-hydrogen", "#b8befc"), ("unlock", "", "#e790a9"),
             ("branch", "main", "#9bdaea"), ("bolt", "32.6/s", "#a3e0d5"), ("chip", "27%", "#f4e3b1"),
             ("database", "0%", "#efb68a"), ("clock", "4.8m", "#b0e1a2"))
STROKE = 1.4


MARK = 1.4  # columns a mark takes: Nerd Font icons run a little wider than a cell
EDGE_PAD = 0.3  # columns of breath inside each block; statusline.sh writes none, but a drawn edge is sharper


def block_width(i: int) -> float:
    """A block as statusline.sh writes it, `[mark ]label`, plus ` ↻` on the last; no padding of its own."""
    mark, label, _ = POWERLINE[i]
    cells = (MARK if mark else 0) + (1 if mark and label else 0) + len(label) + (2 if i == len(POWERLINE) - 1 else 0)
    return CH * (cells + 2 * EDGE_PAD)


# The card is as wide as the status line, the widest row, with the same margin as the left; a chevron is one cell.
WIDTH = PAD_X * 2 + sum(block_width(i) + CH for i in range(len(POWERLINE)))


def icon(name: str, cx: float, cy: float, bg: str) -> str:
    """A status line mark, about 11 px, in the ink, centred on (cx, cy); `bg` cuts details out of solids."""
    line = f'fill="none" stroke="{INK}" stroke-width="{STROKE}" stroke-linecap="round" stroke-linejoin="round"'
    if name == "unlock":    # nf-fa-unlock: a padlock, its shackle open
        return (f'<rect x="{cx - 4:.1f}" y="{cy - 0.5:.1f}" width="8" height="6" rx="1.2" fill="{INK}"/>'
                f'<path d="M{cx - 2.6:.1f},{cy - 0.5:.1f} v-2.4 a2.6,2.6 0 0 1 5.2,0 v-0.6" {line}/>')
    if name == "branch":    # nf-pl-branch: a line, and a branch curving off it
        return (f'<path d="M{cx - 2.5:.1f},{cy - 5:.1f} V{cy + 5:.1f} M{cx + 2.5:.1f},{cy - 2.5:.1f} '
                f'C{cx + 2.5:.1f},{cy + 1:.1f} {cx - 2.5:.1f},{cy + 0.5:.1f} {cx - 2.5:.1f},{cy + 3:.1f}" {line}/>'
                f'<circle cx="{cx + 2.5:.1f}" cy="{cy - 3.4:.1f}" r="1.6" fill="{INK}"/>')
    if name == "bolt":      # nf-fa-bolt
        return (f'<path d="M{cx + 1.2:.1f},{cy - 6:.1f} L{cx - 3.6:.1f},{cy + 1:.1f} H{cx - 0.2:.1f} '
                f'L{cx - 1.2:.1f},{cy + 6:.1f} L{cx + 3.6:.1f},{cy - 1:.1f} H{cx + 0.2:.1f}Z" fill="{INK}"/>')
    if name == "chip":      # nf-fa-microchip: a die with three pins a side
        pins = "".join(f"M{cx + d:.1f},{cy - 5.6:.1f} v1.6 M{cx + d:.1f},{cy + 4:.1f} v1.6 "
                       f"M{cx - 5.6:.1f},{cy + d:.1f} h1.6 M{cx + 4:.1f},{cy + d:.1f} h1.6 " for d in (-2.2, 0, 2.2))
        return (f'<rect x="{cx - 4:.1f}" y="{cy - 4:.1f}" width="8" height="8" rx="1" fill="{INK}"/>'
                f'<rect x="{cx - 1.6:.1f}" y="{cy - 1.6:.1f}" width="3.2" height="3.2" fill="{bg}"/>'
                f'<path d="{pins}" fill="none" stroke="{INK}" stroke-width="1.1"/>')
    if name == "database":  # nf-fa-database: a cylinder in three bands
        body = (f'M{cx - 4.6:.1f},{cy - 3.6:.1f} v7.2 a4.6,1.9 0 0 0 9.2,0 v-7.2 a4.6,1.9 0 0 0 -9.2,0Z')
        bands = "".join(f'<path d="M{cx - 4.6:.1f},{cy + dy:.1f} a4.6,1.9 0 0 0 9.2,0" fill="none" stroke="{bg}" '
                        f'stroke-width="0.9"/>' for dy in (-3.6, -0.6, 2.4))
        return f'<path d="{body}" fill="{INK}"/>' + bands
    if name == "clock":     # nf-fa-clock_o
        return (f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="5" {line}/>'
                f'<path d="M{cx:.1f},{cy - 3:.1f} V{cy:.1f} L{cx + 2.2:.1f},{cy + 1.4:.1f}" {line}/>')
    if name == "refresh":   # the keepalive mark, `↻`
        return (f'<path d="M{cx + 3.6:.1f},{cy + 1:.1f} A3.8,3.8 0 1 1 {cx + 1.4:.1f},{cy - 3.5:.1f}" {line}/>'
                f'<path d="M{cx - 0.4:.1f},{cy - 5.6:.1f} L{cx + 2.4:.1f},{cy - 3.6:.1f} L{cx - 0.2:.1f},{cy - 1.4:.1f}" {line}/>')
    raise ValueError(name)
GREEN, BLUE = "#7fb685", f"#{P.GEMINI_BLUE:06X}"
TICK = 0.1                             # the spinner's frame and the band's column step (s)
VERB, SECONDS = "Starhopping…", range(12, 24)


def star(cx: float, cy: float, r: float) -> str:
    """A four-point star with concave sides, `✦`, centred on (cx, cy)."""
    k = r * 0.18
    return (f"M{cx},{cy - r} C{cx + k},{cy - k} {cx + k},{cy - k} {cx + r},{cy} "
            f"C{cx + k},{cy + k} {cx + k},{cy + k} {cx},{cy + r} "
            f"C{cx - k},{cy + k} {cx - k},{cy + k} {cx - r},{cy} "
            f"C{cx - k},{cy - k} {cx - k},{cy - k} {cx},{cy - r}Z")


def breath() -> tuple[list[str], list[float]]:
    """Each frame's color and scale: `∙` and `⋅` are the star seen small (Maple Mono: 170, 240, 572)."""
    colors, scales = [], []
    for glyph, light, hue in P.SPINNER_BREATH:
        rgb = P._breath_frame(glyph, light, hue).split(b"38;2;")[1].split(b"m")[0].split(b";")
        colors.append("#%02x%02x%02x" % tuple(int(c) for c in rgb))
        scales.append({"∙": 0.30, "⋅": 0.42, "✦": 1.0}[glyph])
    return colors, scales


def band_frames(n: int) -> list[list[str]]:
    """The verb's colors at each step of one swing, as RunningLightWindow and LitWindow place the band."""
    w = min(n, 5)
    period = 2 * (n + w + 5)
    frames = []
    for t in range(period):
        p = t if t < n + w + 6 else period - t
        start = p - w - 3
        frames.append([P.GEMINI_BAND_DARK[(i - start) * len(P.GEMINI_BAND_DARK) // w]
                       if start <= i < start + w else BLUE for i in range(n)])
    return frames


def discrete(attr: str, values: list[str], dur: float) -> str:
    return (f'<animate attributeName="{attr}" values="{";".join(values)}" dur="{dur:g}s" '
            f'calcMode="discrete" repeatCount="indefinite"/>')


def text(x: float, y: float, body: str, fill: str = FG, extra: str = "") -> str:
    return f'<text x="{x:.1f}" y="{y:.1f}" fill="{fill}"{extra}>{body}</text>'


def main() -> None:
    rows = 11
    height = PAD_Y * 2 + rows * ROW - 8  # the last row's descent is its own bottom margin
    y = lambda r: PAD_Y + r * ROW + SIZE          # baseline of row r
    mid = lambda r: PAD_Y + r * ROW + SIZE * 0.62  # optical middle of row r
    col = lambda c: PAD_X + c * CH
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH:.0f}" height="{height}" '
           f'viewBox="0 0 {WIDTH:.0f} {height}" font-family="{FONT}" font-size="{SIZE}">',
           f'<rect x="0.5" y="0.5" width="{WIDTH - 1:.0f}" height="{height - 1}" rx="10" fill="{BG}" stroke="{EDGE}"/>']

    # The user's turn, on its bar.
    out.append(f'<rect x="1" y="{PAD_Y - 4}" width="{WIDTH - 2:.0f}" height="{ROW}" fill="{BAR}"/>')
    out.append(text(col(0), y(0), "&gt;", FAINT) + text(col(2), y(0), "refine the running line"))

    # A finished thought, folded: `∴` drawn as three dots.
    for dx, dy in ((0.5, -1), (0.12, 0.35), (0.88, 0.35)):
        out.append(f'<circle cx="{col(dx):.1f}" cy="{mid(2) + dy * 4:.1f}" r="1.25" fill="{FAINT}"/>')
    out.append(text(col(2), y(2), "Thought for 7s (Planning the light)", FAINT, ' font-style="italic"'))

    # A finished tool call: `⋆`, small and solid.
    out.append(f'<path d="{star(col(0.5), mid(4), 4.6)}" fill="{GREEN}"/>')
    out.append(text(col(2), y(4), '<tspan font-weight="600">Ran</tspan> '
                    f'<tspan fill="{FAINT}">(git log --oneline -n 8) (ctrl+o to expand)</tspan>'))

    # The running line: the star breathes, the band swings, the seconds tick.
    colors, scales = breath()
    frames = len(colors)
    cx, cy = col(0.5), mid(6)
    scale = ";".join(f"{cx * (1 - s):.2f} {cy * (1 - s):.2f}" for s in scales)
    out.append(f'<g><animateTransform attributeName="transform" type="translate" values="{scale}" '
               f'dur="{frames * TICK:g}s" calcMode="discrete" repeatCount="indefinite"/>'
               f'<g><animateTransform attributeName="transform" type="scale" '
               f'values="{";".join(f"{s}" for s in scales)}" dur="{frames * TICK:g}s" calcMode="discrete" '
               f'repeatCount="indefinite"/>'
               f'<path d="{star(cx, cy, 6.2)}" fill="{colors[0]}">{discrete("fill", colors, frames * TICK)}</path>'
               f'</g></g>')
    swing = band_frames(len(VERB))
    for i, ch in enumerate(VERB):
        out.append(f'<text x="{col(2 + i):.1f}" y="{y(6):.1f}" fill="{BLUE}">{escape(ch)}'
                   f'{discrete("fill", [f[i] for f in swing], len(swing) * TICK)}</text>')
    aside_x = col(2 + len(VERB) + 1)
    n = len(SECONDS)
    for k, s in enumerate(SECONDS):
        on = ["0"] * n
        on[k] = "1"
        out.append(f'<text x="{aside_x:.1f}" y="{y(6):.1f}" fill="{ASIDE}" opacity="{on[0]}">'
                   f'({s}s · thinking with high effort){discrete("opacity", on, n)}</text>')

    # The input between its rules, and the footer.
    for r in (7, 9):
        out.append(f'<line x1="{PAD_X}" x2="{WIDTH - PAD_X:.1f}" y1="{mid(r):.1f}" y2="{mid(r):.1f}" stroke="{RULE}"/>')
    out.append(text(col(0), y(8), "&gt;", FAINT))
    out.append(f'<rect x="{col(2):.1f}" y="{y(8) - SIZE + 2:.1f}" width="{CH:.1f}" height="{SIZE + 3}" fill="{FG}">'
               f'{discrete("opacity", ["1", "0"], 1.2)}</rect>')
    # The status line: each block's mark and text, then a one-cell chevron into the next block.
    x, top, h = float(PAD_X), PAD_Y + 10 * ROW, ROW - 2
    cy = top + h / 2
    for i, (mark, label, color) in enumerate(POWERLINE):
        width = block_width(i)
        nxt = POWERLINE[i + 1][2] if i + 1 < len(POWERLINE) else None
        out.append(f'<rect x="{x:.1f}" y="{top}" width="{width + 1:.1f}" height="{h}" fill="{color}"/>')
        if nxt:
            out.append(f'<rect x="{x + width:.1f}" y="{top}" width="{CH + 1:.1f}" height="{h}" fill="{nxt}"/>')
        out.append(f'<path d="M{x + width:.1f},{top} L{x + width + CH:.1f},{cy} L{x + width:.1f},{top + h}Z" fill="{color}"/>')
        at = x + EDGE_PAD * CH
        if mark:
            out.append(icon(mark, at + MARK * CH / 2, cy, color))
            at += (MARK + 1) * CH
        if label:
            out.append(text(at, cy + SIZE * 0.36, label, INK, ' font-weight="600"'))
            at += len(label) * CH
        if i == len(POWERLINE) - 1:
            out.append(icon("refresh", at + 1.5 * CH, cy + 0.5, color))
        x += width + CH
    out.append("</svg>")
    (REPO / "assets/hero.svg").write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
