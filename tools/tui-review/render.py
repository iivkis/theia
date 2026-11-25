#!/usr/bin/env python3
"""Render the actual Ratatui cell grid using a fixed Linux font and palette."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

PALETTE = ["#161b22", "#e05a5a", "#69b96e", "#d6b85d", "#609bdf", "#b980d9", "#62c0c4", "#c9d1d9",
           "#69717c", "#ff8585", "#8fdb91", "#ffe08c", "#8cbaff", "#d6a6ff", "#91ebec", "#ffffff"]
NAMES = dict(zip(["Black","Red","Green","Yellow","Blue","Magenta","Cyan","Gray",
                  "DarkGray","LightRed","LightGreen","LightYellow","LightBlue","LightMagenta","LightCyan","White"], PALETTE))
def color(value, default):
    if value == "Reset":
        return default
    if value in NAMES:
        return NAMES[value]
    match = re.fullmatch(r"Rgb\((\d+),\s*(\d+),\s*(\d+)\)", value)
    if match:
        return tuple(map(int, match.groups()))
    match = re.fullmatch(r"Indexed\((\d+)\)", value)
    if match:
        index = int(match[1])
        if index < 16:
            return PALETTE[index]
        if index < 232:
            n = index - 16
            levels = [0, 95, 135, 175, 215, 255]
            return tuple(levels[i] for i in (n // 36, n // 6 % 6, n % 6))
        return (8 + 10 * (index - 232),) * 3
    raise ValueError(f"unsupported terminal color: {value}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cells", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--source-sha", required=True)
    args = ap.parse_args()
    assert re.fullmatch(r"[0-9a-f]{40}", args.source_sha)
    args.output.mkdir(parents=True, exist_ok=False)
    fontdir = Path("/usr/share/fonts/truetype/dejavu")
    normal = ImageFont.truetype(str(fontdir / "DejaVuSansMono.ttf"), 16)
    bold = ImageFont.truetype(str(fontdir / "DejaVuSansMono-Bold.ttf"), 16)
    italic = ImageFont.truetype(str(fontdir / "DejaVuSansMono-Oblique.ttf"), 16)
    bolditalic = ImageFont.truetype(str(fontdir / "DejaVuSansMono-BoldOblique.ttf"), 16)
    cw, ch = 10, 21
    entries = []
    for source in sorted(args.cells.glob("*.cells")):
        name = source.stem
        assert re.fullmatch(r"[a-z0-9-]+", name)
        lines = source.read_text(encoding="utf-8").splitlines()
        w, h = map(int, lines[0].split("\t"))
        assert (w, h) == (120, 40) and len(lines) == 1 + w*h, name
        image = Image.new("RGB", (cw*w, ch*h), "#161b22")
        draw = ImageDraw.Draw(image)
        glyphs = []
        for i, row in enumerate(lines[1:]):
            fg, bg, mods, symbol = row.split("\t")
            fg, bg = color(fg, "#c9d1d9"), color(bg, "#161b22")
            if "REVERSED" in mods:
                fg, bg = bg, fg
            x, y = i % w * cw, i // w * ch
            draw.rectangle((x, y, x+cw-1, y+ch-1), fill=bg)
            glyphs.append((x,y,fg,mods,bytes.fromhex(symbol).decode("utf-8")))
        # Paint backgrounds first, so wide glyphs are not erased by neighbors.
        for x,y,fg,mods,symbol in glyphs:
            if "HIDDEN" in mods or not symbol.strip():
                continue
            font = bolditalic if "BOLD" in mods and "ITALIC" in mods else bold if "BOLD" in mods else italic if "ITALIC" in mods else normal
            draw.text((x,y+16), symbol, font=font, fill=fg, anchor="ls")
            if "UNDERLINED" in mods:
                draw.line((x,y+18,x+cw-1,y+18), fill=fg)
            if "CROSSED_OUT" in mods:
                draw.line((x,y+10,x+cw-1,y+10), fill=fg)
        filename = name + ".png"
        path = args.output / filename
        image.save(path, optimize=True)
        entries.append({"scenario":name, "file":filename, "sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                        "state_fixture":name.startswith("state-")})
    required = {"home-role-selection","help","server-page-overview","server-page-connections","server-page-users",
                "client-page-overview","client-page-profiles","client-action-invitation-import","server-action-reality-wizard"}
    assert required <= {e["scenario"] for e in entries}
    hashes = {e["scenario"]: e["sha256"] for e in entries}
    assert hashes["server-action-server-process"] != hashes["server-page-connections"], "server process screenshot duplicates connections"
    assert len(entries) >= 50, f"unexpectedly incomplete gallery: {len(entries)}"
    manifest = {"schema_version":1,"source_sha":args.source_sha,"platform":"linux","columns":120,"rows":40,
                "pixel_width":1200,"pixel_height":840,"renderer":"Ratatui TestBackend + DejaVu Sans Mono",
                "scope":"Offline fixture scenarios; not a real terminal emulator or live runtime acceptance.",
                "screens":entries}
    (args.output/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    index = ["# Theia TUI visual review", "", f"Source: {args.source_sha}", "",
             "Linux · 120×40 · actual production renderer cells. State fixtures and unavailable actions are not runtime success.", "",
             "Review layout, hierarchy, readability, labels, empty/error states and navigation. Report missing screens; never infer unobserved states.", ""]
    for entry in entries:
        index.extend([f"## {entry['scenario']}", "", f"![{entry['scenario']}]({entry['file']})", ""])
    (args.output/"README.md").write_text("\n".join(index), encoding="utf-8")
if __name__ == "__main__":
    main()
