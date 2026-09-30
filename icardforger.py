#!/usr/bin/env python3
"""
ICardForger — tampers with the name field in an ICard QR payload
and saves it as a new card image. The signature will be invalid
when scanned with qricardreader.py, demonstrating forgery detection.

Usage:
  python3 icardforger.py [--image icard/icard_back.png]
                         [--background Background.png]
                         [--name "FORGED_NAME"]
                         [--out forgedIcard.png]
"""

import sys
import argparse
import gzip
import math
from pathlib import Path

sys.set_int_max_str_digits(0)

import zxingcpp
import qrcode
from PIL import Image, ImageDraw, ImageFont

DPI    = 300
CARD_W = round(85.6 / 25.4 * DPI)
CARD_H = round(54.0 / 25.4 * DPI)

JP2_SOC = b'\xff\x4f\xff\x51'
JP2_EOC = b'\xff\xd9'


# ─────────────────────────── helpers ─────────────────────────────────

def load_font(size, bold=False):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"
        if bold else "/usr/share/fonts/TTF/DejaVuSans.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def fit_background(path):
    bg    = Image.open(path).convert("RGB")
    scale = max(CARD_W / bg.width, CARD_H / bg.height)
    new_size = (math.ceil(bg.width * scale), math.ceil(bg.height * scale))
    bg    = bg.resize(new_size, Image.Resampling.LANCZOS)
    left  = (bg.width  - CARD_W) // 2
    top   = (bg.height - CARD_H) // 2
    return bg.crop((left, top, left + CARD_W, top + CARD_H)).convert("RGBA")


def decode_qr(image_path: str) -> str:
    img     = Image.open(image_path)
    results = zxingcpp.read_barcodes(img)
    if not results:
        raise RuntimeError(f"No QR code found in: {image_path}")
    return results[0].text


def decompress(decimal_str: str) -> bytes:
    big_int   = int(decimal_str)
    num_bytes = (big_int.bit_length() + 7) // 8
    raw       = big_int.to_bytes(num_bytes, byteorder='big')
    if raw[:2] != b'\x1f\x8b':
        raise RuntimeError("Not a gzip payload")
    return gzip.decompress(raw)


def recompress(data: bytes) -> str:
    compressed  = gzip.compress(data, compresslevel=9)
    big_int     = int.from_bytes(compressed, byteorder='big')
    return str(big_int)


def tamper_name(decompressed: bytes, new_name: str) -> bytes:
    """
    Replace the name field (field index 1 after version+flag prefix)
    in the 0xFF-delimited payload WITHOUT touching the signature.
    The signature will then cover different data than what's present
    → detected as forged on verification.
    """
    # Layout: V5 \xff <flag> \xff <ref_id> \xff <NAME> \xff ...
    # Split on \xff but preserve the photo binary (which contains \xff bytes)
    # Strategy: split only up to the JP2 SOC marker, leave the rest intact.

    jp2_pos = decompressed.find(JP2_SOC)
    if jp2_pos == -1:
        raise RuntimeError("JP2 SOC not found — cannot locate photo boundary")

    text_part  = decompressed[:jp2_pos]   # all \xFF-delimited fields
    binary_part = decompressed[jp2_pos:]   # photo + signature + email

    fields = text_part.split(b'\xff')
    # fields[0] = b'V5'
    # fields[1] = email_mobile_flag
    # fields[2] = ref_id
    # fields[3] = NAME  ← tamper here
    if len(fields) < 4:
        raise RuntimeError("Unexpected field count — cannot locate name field")

    original_name = fields[3].decode('utf-8', errors='replace')
    print(f"  Original name : {original_name}")
    print(f"  Forged name   : {new_name}")

    fields[3] = new_name.encode('utf-8')

    tampered_text = b'\xff'.join(fields)
    return tampered_text + binary_part   # signature is unchanged → mismatch


def render_back(background_path: str, qr_decimal: str, organisation: str) -> Image.Image:
    card = fit_background(background_path)
    draw = ImageDraw.Draw(card)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=2,
    )
    qr.add_data(qr_decimal)
    qr.make(fit=True)
    print(f"  QR version: {qr.version}")
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    max_qr = min(CARD_H - 180, CARD_W - 180)
    qr_img.thumbnail((max_qr, max_qr), Image.Resampling.LANCZOS)

    qr_x = (CARD_W - qr_img.width)  // 2
    qr_y = 70

    pad   = 22
    plate = Image.new("RGBA", (qr_img.width + 2 * pad, qr_img.height + 2 * pad), "white")
    card.alpha_composite(plate, (qr_x - pad, qr_y - pad))
    card.paste(qr_img, (qr_x, qr_y))

    org_font  = load_font(42, bold=True)
    small_font = load_font(21)
    max_width = CARD_W - 80

    while draw.textbbox((0, 0), organisation, font=org_font)[2] > max_width \
            and org_font.size > 22:
        org_font = load_font(org_font.size - 2, bold=True)

    bbox  = draw.textbbox((0, 0), organisation, font=org_font)
    org_x = (CARD_W - (bbox[2] - bbox[0])) // 2
    org_y = qr_y + qr_img.height + 45
    draw.text((org_x, org_y), organisation, font=org_font, fill="white")

    note = "Scan to verify"
    nb   = draw.textbbox((0, 0), note, font=small_font)
    draw.text(
        ((CARD_W - (nb[2] - nb[0])) // 2, CARD_H - 45),
        note, font=small_font, fill="white",
    )

    return card


# ─────────────────────────── main ────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ICard forger — demo of tampering detection")
    parser.add_argument("--image",      default="icard/icard_back.png")
    parser.add_argument("--background", default="Background.png")
    parser.add_argument("--name",       default="FORGED_NAME",
                        help="Replacement name to inject")
    parser.add_argument("--org",        default="My Organisation",
                        help="Organisation text on the card (keep same as original)")
    parser.add_argument("--out",        default="forgedIcard.png")
    args = parser.parse_args()

    image_path = Path(args.image)
    bg_path    = Path(args.background)

    if not image_path.is_file():
        print(f"Error: image not found: {image_path}"); sys.exit(1)
    if not bg_path.is_file():
        print(f"Error: background not found: {bg_path}"); sys.exit(1)

    print("\n[1] Decoding QR from card back…")
    decimal_str = decode_qr(str(image_path))
    print(f"  Decoded {len(decimal_str)} digits")

    print("\n[2] Decompressing payload…")
    decompressed = decompress(decimal_str)
    print(f"  Decompressed size: {len(decompressed)} bytes")

    print("\n[3] Tampering with name field…")
    tampered = tamper_name(decompressed, args.name)

    print("\n[4] Recompressing tampered payload…")
    forged_decimal = recompress(tampered)
    print(f"  Forged decimal string: {len(forged_decimal)} digits")

    print("\n[5] Rendering forged card…")
    card = render_back(str(bg_path), forged_decimal, args.org)
    out_path = Path(args.out)
    card.convert("RGB").save(str(out_path), dpi=(DPI, DPI), optimize=True)
    print(f"  Saved: {out_path}")

    print("\n[6] Done.")
    print(f"  Scan {out_path} with qricardreader.py — it should report:")
    print(f"  ✗  SIGNATURE INVALID — the name was changed but the")
    print(f"     RSA signature still covers the original payload.")
    print()


if __name__ == "__main__":
    main()
