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
    required.update({"client-first-key-input", "client-first-key-trust", "client-first-key-save-review", "client-first-key-saved", "client-first-key-connect"})
    required.update(["server-first-reality-dns-expanded","state-reality-step4-tls-consent","state-reality-step4-tls-progress","state-reality-step4-tls-recheck","state-reality-step5-ranked-review","state-reality-step5-no-eligible","state-reality-step6-saving","state-reality-step6-save-error","state-reality-step6-save-uncertain"])
    required.update(["state-reality-step4-tls-expanded","state-reality-step3-dns-progress","state-reality-step5-ranked-expanded","state-reality-step5-long-report","state-reality-step5-no-eligible-expanded","state-reality-step6-save-inspection","state-reality-step6-success","state-reality-step2-extra-sources","state-reality-step1-grant-picker"])
    required.update(["state-reality-step2-domain-editor","state-reality-step5-long-report-scrolled","state-reality-step6-key-handoff"])
    required.update(["server-page-overview","server-page-connections","server-page-users","server-page-users-disabled","server-page-management","server-page-traffic","server-page-settings","server-page-diagnostics","client-page-overview","client-page-profiles","client-page-import","client-page-proxy","client-page-traffic","client-page-settings","server-overview-next-step","client-overview-next-step","server-sections-focus","client-sections-focus","client-action-invitation-import","server-action-recover-user"])
    obsolete = set(["server-page-invitations","client-action-reality-import","server-command-menu","client-command-menu","server-focus-actions","client-focus-actions","server-action-apply-rights","server-action-restart-preflight","server-traffic-monitor-idle","server-action-server-process","server-action-delete-user"])
    actual = {e["scenario"] for e in entries}
    assert not obsolete & actual, f"obsolete duplicate screens: {sorted(obsolete & actual)}"
    required.update(["server-page-advanced","client-page-advanced","client-page-import-masked","server-page-users-ungranted","server-action-delete-user-confirm"])
    required.update(["server-page-routing","client-page-routing","client-page-diagnostics","server-routing-rules","server-routing-edit","server-routing-geodata","server-page-users-observed","client-routing-fresh","client-routing-expired","client-routing-unconfirmed"])
    required.update(["state-profile-diagnostics-choose","state-profile-diagnostics-custom","state-profile-diagnostics-validation-error","state-profile-diagnostics-fetching","state-profile-diagnostics-consent","state-profile-diagnostics-running","state-profile-diagnostics-completed","state-profile-diagnostics-partial","state-profile-diagnostics-details","state-profile-diagnostics-blocked","state-profile-diagnostics-failed"])
    required.update(["state-reality-step5-manual-choice", "state-reality-step5-manual-selected", "server-routing-geosite-picker", "server-routing-geoip-picker"])
    required.update(["server-routing-geodata-marked", "server-routing-geodata-empty", "server-routing-geodata-missing", "server-routing-geodata-added"])
    assert not required & obsolete, "contradictory gallery contract"
    missing = required - actual
    assert not missing, f"missing required screens: {sorted(missing)}"
    hashes = {e["scenario"]: e["sha256"] for e in entries}
    assert hashes["server-page-management"] != hashes["server-page-connections"], "management screenshot duplicates connections"
    diagnostic_names = sorted(name for name in actual if name.startswith("state-profile-diagnostics-"))
    assert len({hashes[name] for name in diagnostic_names}) == len(diagnostic_names), "duplicate profile diagnostic states"
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
