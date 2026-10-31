
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent.parent
OUT = HERE / "assets"
OUT.mkdir(exist_ok=True)

FONT_BOLD = Path("C:/Windows/Fonts/segoeuib.ttf")
FONT_BLACK = Path("C:/Windows/Fonts/seguibl.ttf")

TOP = (58, 140, 255)
BOTTOM = (18, 71, 191)
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SUPERSAMPLE = 8


def rounded_mask(size: int, radius_ratio: float) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    r = int(size * radius_ratio)
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=r, fill=255)
    return mask


def gradient(size: int) -> Image.Image:
    img = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        t = t * t * (3 - 2 * t)
        px = tuple(round(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3))
        img.putpixel((0, y), px)
    return img.resize((size, size), Image.NEAREST)


def add_gloss(img: Image.Image, mask: Image.Image) -> None:
    """顶部柔和高光：模拟受光面，让纯色块看起来有体积。"""
    size = img.size[0]
    gloss = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(gloss)
    height = int(size * 0.55)
    for y in range(height):
        alpha = int(18 * (1 - y / height) ** 1.4)
        draw.line([(0, y), (size, y)], fill=alpha)
    white = Image.new("RGBA", (size, size), (255, 255, 255, 255))
    img.paste(white, (0, 0), gloss)


def render(size: int) -> Image.Image:
    """按目标尺寸渲染（内部先放大 SUPERSAMPLE 倍再降采样）。"""
    big = size * SUPERSAMPLE
    small = size <= 24
    tiny = size <= 20
    radius_ratio = 0.16 if tiny else (0.20 if small else 0.22)
    font_file = FONT_BLACK if (small and FONT_BLACK.is_file()) else FONT_BOLD

    canvas = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    mask = rounded_mask(big, radius_ratio)

    bg = gradient(big).convert("RGBA")
    add_gloss(bg, mask)
    bg.putalpha(mask)
    canvas.paste(bg, (0, 0), bg)

    ratio = (0.66 if tiny else 0.58) if small else 0.50
    font = ImageFont.truetype(str(font_file), int(big * ratio))

    probe = ImageDraw.Draw(Image.new("L", (big, big)))
    box = probe.textbbox((0, 0), "Hi", font=font)
    tw, th = box[2] - box[0], box[3] - box[1]

    x = (big - tw) / 2 - box[0]
    y = (big - th) / 2 - box[1] - big * 0.012

    if not tiny:
        shadow = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        ImageDraw.Draw(shadow).text(
            (x, y + big * 0.012), "Hi", font=font, fill=(8, 32, 84, 90)
        )
        from PIL import ImageFilter

        shadow = shadow.filter(ImageFilter.GaussianBlur(big * 0.008))
        canvas.alpha_composite(
            Image.composite(shadow, Image.new("RGBA", (big, big), (0, 0, 0, 0)), mask)
        )

    ImageDraw.Draw(canvas).text((x, y), "Hi", font=font, fill=(255, 255, 255, 255))

    return canvas.resize((size, size), Image.LANCZOS)



def write_dib_container(path: Path, sizes=(16, 20, 24, 32, 48)) -> None:
    """自建容器：直接存 32 位 DIB，供 Rust 侧 CreateIconFromResourceEx 使用。

    为什么不用 .ico：PIL 存 ICO 时内部是 PNG 帧，而 CreateIconFromResourceEx
    只认 RT_ICON 的 DIB 布局（BITMAPINFOHEADER + 逆序 BGRA + AND 掩码）。
    自建容器省掉在 Rust 里解 PNG 的麻烦，也保证一定建得出 HICON。
    """
    import struct

    payloads = []
    for s in sizes:
        img = render(s).convert("RGBA")
        px = img.load()
        xor = bytearray()
        for y in range(s - 1, -1, -1):
            for x in range(s, ):
                r, g, b, a = px[x, y]
                xor += bytes((b, g, r, a))
        row = ((s + 31) // 32) * 4
        and_mask = bytes(row * s)
        header = struct.pack(
            "<IiiHHIIiiII",
            40,
            s,
            s * 2,
            1,
            32,
            0,
            0,
            0, 0, 0, 0,
        )
        payloads.append((s, header + bytes(xor) + and_mask))

    buf = bytearray(struct.pack("<I", len(payloads)))
    for s, data in payloads:
        buf += struct.pack("<II", s, len(data))
        buf += data
    path.write_bytes(bytes(buf))
    print(f"已生成 {path.name} ({len(buf)} 字节, {len(payloads)} 个尺寸)")


def main() -> None:
    frames = [render(s) for s in SIZES]
    ico = OUT / "hwshare.ico"
    frames[-1].save(ico, format="ICO", sizes=[(s, s) for s in SIZES])
    print(f"已生成 {ico} ({ico.stat().st_size} 字节, {len(SIZES)} 个尺寸)")

    preview = Image.new("RGBA", (256 * 3 + 80, 300), (245, 247, 250, 255))
    for i, s in enumerate([16, 32, 256]):
        frame = render(s)
        shown = frame.resize((256, 256), Image.NEAREST) if s <= 32 else frame
        preview.alpha_composite(shown, (20 + i * 276, 20))
    preview.convert("RGB").save(OUT / "preview.png")

    bar = Image.new("RGBA", (420, 48), (32, 32, 32, 255))
    x = 16
    for s in (16, 20, 24, 32):
        bar.alpha_composite(render(s), (x, (48 - s) // 2))
        x += s + 16
    bar.resize((840, 96), Image.NEAREST).convert("RGB").save(OUT / "preview-tray.png")
    print("已生成 assets/preview.png 与 assets/preview-tray.png")
    write_dib_container(OUT / "tray_icon.bin")


if __name__ == "__main__":
    main()
