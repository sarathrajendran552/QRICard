#!/usr/bin/env python3
"""
Create a two-sided CR-80 I-Card with a UIDAI-style signed QR code.

The back QR encodes a gzip-compressed, RSA-signed binary payload that is
directly compatible with the Aadhaar Secure QR (v2) decoder script
(aadhaar_qr_decode.py), including:

  - Version header  : V5
  - Email/Mobile flag
  - 0xFF-delimited demographic fields
  - Embedded JPEG2000 face photo (60x60, compressed with OpenCV)
  - RSA-2048 / SHA-256 signature (last 256 bytes)
  - Masked email appended after the signature (outside signed region)

The whole signed block is gzip-compressed and encoded as a decimal integer
string so that QR numeric mode can be used for maximum density.

Expected files in the working directory:
  Background.png
  certsnkeys/icard_sign.key    (from gen_cert.py)

Usage:
  python3 make_icard.py \\
      --name        "John Doe" \\
      --dob         "01/01/1990" \\
      --address     "123 Example Street, Bengaluru" \\
      --organisation "Example Organisation" \\
      --image       "SampleFace.jpg" \\
      --district    "Bengaluru Urban" \\
      --state       "Karnataka" \\
      --pincode     "560001" \\
      --mobile-last4 "1234" \\
      --email-masked "jXXXX@gXXXX.com"

Outputs:
  icard/icard_front.png
  icard/icard_back.png
"""

import argparse
import gzip
import math
import sys
from pathlib import Path

# Python 3.11+ caps int→str conversion at 4300 digits by default.
# Our QR payload encodes to a large decimal integer, so we remove the cap.
sys.set_int_max_str_digits(0)

import cv2
import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

DPI      = 300
CARD_W   = round(85.6 / 25.4 * DPI)
CARD_H   = round(54.0 / 25.4 * DPI)
PHOTO_SZ     = 60      # pixels — same as UIDAI
PHOTO_MAX_B  = 950     # target max bytes for embedded photo (UIDAI is ~900)


# ───────────────────────────── helpers ──────────────────────────────

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
    bg = Image.open(path).convert("RGB")
    scale = max(CARD_W / bg.width, CARD_H / bg.height)
    new_size = (math.ceil(bg.width * scale), math.ceil(bg.height * scale))
    bg = bg.resize(new_size, Image.Resampling.LANCZOS)
    left = (bg.width - CARD_W) // 2
    top  = (bg.height - CARD_H) // 2
    return bg.crop((left, top, left + CARD_W, top + CARD_H)).convert("RGBA")


def fit_image(image_path, size):
    img = Image.open(image_path).convert("RGB")
    w, h = size
    scale = max(w / img.width, h / img.height)
    new_size = (math.ceil(img.width * scale), math.ceil(img.height * scale))
    img = img.resize(new_size, Image.Resampling.LANCZOS)
    left = (img.width - w) // 2
    top  = (img.height - h) // 2
    return img.crop((left, top, left + w, top + h))


def draw_wrapped_text(draw, text, xy, font, fill, max_width, line_spacing=8):
    words = str(text).split()
    lines, current = [], ""
    for word in words:
        candidate = word if not current else current + " " + word
        if draw.textbbox((0, 0), candidate, font=font)[2] <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)

    x, y = xy
    bbox   = draw.textbbox((x, y), "Ag", font=font)
    line_h = bbox[3] - bbox[1]
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += line_h + line_spacing
    return y


# ──────────────────────── photo compression ─────────────────────────

def compress_photo_jp2(image_path: str) -> bytes:
    """
    Encode the face photo as a raw JPEG2000 codestream using glymur
    (OpenJPEG backend) with explicit bitrate targeting — the same
    approach UIDAI uses with JJ2000.

    Strategy:
    - Colour (BGR→RGB), no grayscale conversion — UIDAI preserves colour.
    - Centre-square crop → resize to PHOTO_SZ x PHOTO_SZ with LANCZOS.
    - Binary-search the compression ratio until the output fits within
      PHOTO_MAX_B bytes, giving the best quality that still fits.
    - Output is a raw J2K codestream (not a JP2 container box), ending
      with the EOC marker 0xFF 0xD9, exactly as UIDAI embeds it.
    """
    import tempfile
    import glymur

    # --- Load and crop ---
    img_bgr = cv2.imread(str(image_path))
    if img_bgr is None:
        raise FileNotFoundError(f"Cannot read image: {image_path}")

    h, w   = img_bgr.shape[:2]
    side   = min(h, w)
    y0     = (h - side) // 2
    x0     = (w - side) // 2
    img_bgr = img_bgr[y0:y0 + side, x0:x0 + side]

    # High-quality downscale with LANCZOS (PIL is better than cv2 for this)
    pil_img  = Image.fromarray(cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB))
    pil_img  = pil_img.resize((PHOTO_SZ, PHOTO_SZ), Image.Resampling.LANCZOS)
    img_rgb  = np.array(pil_img)  # H x W x 3, uint8, RGB

    # --- Binary-search compression ratio for best quality under PHOTO_MAX_B ---
    # cratio = uncompressed_bytes / compressed_bytes
    # At 60x60x3 = 10800 uncompressed bytes, cratio=11 → ~982 bytes
    lo, hi      = 10, 200   # ratio search range
    best_data   = b''
    best_cratio = hi

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = str(Path(tmpdir) / "face.j2k")

        while lo <= hi:
            mid = (lo + hi) // 2
            glymur.Jp2k(
                tmp_path,
                data=img_rgb,
                cratios=[mid],
                numres=2,          # 2 resolution levels (UIDAI uses a few)
            )
            data = Path(tmp_path).read_bytes()

            # glymur writes a JP2 container; we need the raw J2K codestream.
            # The codestream starts at the SOC marker 0xFF 0x4F inside the box.
            soc = data.find(b'\xff\x4f')
            if soc != -1:
                data = data[soc:]

            # Ensure EOC
            if not data.endswith(b'\xff\xd9'):
                data += b'\xff\xd9'

            size = len(data)
            if size <= PHOTO_MAX_B:
                best_data   = data
                best_cratio = mid
                hi = mid - 1          # try lower ratio (higher quality)
            else:
                lo = mid + 1          # too large, increase ratio

    if not best_data:
        raise RuntimeError(
            f"Could not compress photo to under {PHOTO_MAX_B} bytes "
            f"even at cratio={best_cratio}. Try increasing PHOTO_MAX_B."
        )

    print(f"Photo JP2: {len(best_data)} bytes at compression ratio {best_cratio}:1")
    return best_data


# ──────────────────────── QR payload builder ────────────────────────

def build_qr_payload(args, photo_jp2: bytes, key) -> str:
    """
    Build a UIDAI Secure QR v2-compatible payload:

    signed region (0xFF-delimited):
      V5 | <email_mobile_flag> | <last4id><timestamp> |
      name | dob | gender | care_of | district | landmark |
      house | location | pincode | post_office | state |
      vtc | sub_district | po | mobile_last4 | <JP2 bytes>
    + 256-byte RSA signature

    then gzip-compress the whole thing and encode as a decimal integer string.

    Masked email is appended AFTER the signature (outside signed region),
    exactly as in the real Aadhaar QR.
    """
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "000"
    ref_id = (args.id_last4 + ts).encode()

    SEP = b'\xff'

    # Build the address string into UIDAI's field slots
    # (landmark and sub_district left blank to keep it simple)
    fields = [
        b'V5',
        args.email_mobile_flag.encode(),
        ref_id,
        args.name.encode(),
        args.dob.encode(),
        args.gender.encode(),
        args.care_of.encode(),
        args.district.encode(),
        b'',                          # landmark
        args.house.encode(),
        args.location.encode(),
        args.pincode.encode(),
        args.post_office.encode(),
        args.state.encode(),
        args.vtc.encode(),
        b'',                          # sub_district
        args.po.encode(),
        (f'XXXXXX{args.mobile_last4}').encode(),
        b'',                          # extra flag field
    ]

    signed_data = SEP.join(fields) + SEP + photo_jp2

    # Sign with RSA-2048 / SHA-256 / PKCS1v15
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    assert len(signature) == 256

    # Signed block + signature
    payload = signed_data + signature

    # Masked email goes OUTSIDE the signed region (appended after signature)
    payload += args.email_masked.encode('utf-8')

    # gzip-compress
    compressed = gzip.compress(payload, compresslevel=9)

    # Convert bytes → big integer → decimal string (numeric QR mode)
    big_int   = int.from_bytes(compressed, byteorder='big')
    decimal_str = str(big_int)

    return decimal_str


# ──────────────────────── card rendering ────────────────────────────

def create_front(background, name, dob, address, image_path):
    card = fit_background(background)
    draw = ImageDraw.Draw(card)

    margin    = 45
    picture_w = 275
    picture_h = 345
    picture_x = margin
    picture_y = 135

    portrait = fit_image(image_path, (picture_w, picture_h))
    card.paste(portrait, (picture_x, picture_y))
    draw.rectangle(
        [picture_x, picture_y, picture_x + picture_w, picture_y + picture_h],
        outline="white", width=5,
    )

    title_font   = load_font(48, bold=True)
    label_font   = load_font(27, bold=True)
    value_font   = load_font(27)
    address_font = load_font(24)

    panel_x = 355
    panel_y = 125
    panel_w = CARD_W - panel_x - margin
    panel_h = CARD_H - panel_y - 45

    overlay = Image.new("RGBA", card.size, (0, 0, 0, 0))
    odraw   = ImageDraw.Draw(overlay)
    odraw.rounded_rectangle(
        [panel_x, panel_y, panel_x + panel_w, panel_y + panel_h],
        radius=22, fill=(0, 0, 0, 135),
    )
    card = Image.alpha_composite(card, overlay)
    draw = ImageDraw.Draw(card)

    x = panel_x + 25
    y = panel_y + 25

    f = title_font
    while draw.textbbox((0, 0), name, font=f)[2] > panel_w - 50 and f.size > 25:
        f = load_font(f.size - 2, bold=True)
    draw.text((x, y), name, font=f, fill="white")
    y += f.size + 30

    draw.text((x, y), "DOB", font=label_font, fill="white")
    y += 34
    y = draw_wrapped_text(draw, dob, (x, y), value_font, "white", panel_w - 50, 4)
    y += 12

    draw.text((x, y), "ADDRESS", font=label_font, fill="white")
    y += 34
    draw_wrapped_text(draw, address, (x, y), address_font, "white", panel_w - 50, 5)

    return card


def create_back(background, qr_decimal_str, organisation):
    card = fit_background(background)
    draw = ImageDraw.Draw(card)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=2,
    )
    qr.add_data(qr_decimal_str)
    qr.make(fit=True)
    print(f"QR version: {qr.version}  (data length: {len(qr_decimal_str)} digits)")
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    max_qr = min(CARD_H - 180, CARD_W - 180)
    qr_img.thumbnail((max_qr, max_qr), Image.Resampling.LANCZOS)

    qr_x = (CARD_W - qr_img.width) // 2
    qr_y = 70

    pad   = 22
    plate = Image.new("RGBA", (qr_img.width + 2 * pad, qr_img.height + 2 * pad), "white")
    card.alpha_composite(plate, (qr_x - pad, qr_y - pad))
    card.paste(qr_img, (qr_x, qr_y))

    org_font  = load_font(42, bold=True)
    small_font = load_font(21)

    max_width = CARD_W - 80
    while draw.textbbox((0, 0), organisation, font=org_font)[2] > max_width and org_font.size > 22:
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


# ────────────────────────────── main ────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Create a signed CR-80 I-Card with UIDAI-style QR"
    )
    # Identity
    parser.add_argument("--name",          required=True)
    parser.add_argument("--dob",           required=True,  help="DD/MM/YYYY")
    parser.add_argument("--gender",        default="M",    help="M / F / T")
    parser.add_argument("--image",         required=True,  help="Path to photo")

    # Address fields (mirrors UIDAI field order)
    parser.add_argument("--care-of",       default="")
    parser.add_argument("--house",         default="")
    parser.add_argument("--location",      default="")
    parser.add_argument("--landmark",      default="")
    parser.add_argument("--district",      default="")
    parser.add_argument("--vtc",           default="")
    parser.add_argument("--sub-district",  default="")
    parser.add_argument("--po",            default="")
    parser.add_argument("--post-office",   default="")
    parser.add_argument("--state",         default="")
    parser.add_argument("--pincode",       default="")
    parser.add_argument("--address",       default="",
                        help="Full address string shown on card front")

    # Contact
    parser.add_argument("--mobile-last4",  default="0000",
                        help="Last 4 digits of mobile number")
    parser.add_argument("--email-masked",  default="",
                        help="Masked email e.g. jXXXX@gXXXX.com")
    parser.add_argument("--email-mobile-flag", default="3",
                        help="1=email,2=mobile,3=both,0=none")

    # ID
    parser.add_argument("--id-last4",      default="0000",
                        help="Last 4 digits of the card/ID number")

    # Organisation
    parser.add_argument("--organisation",  required=True)

    # Files
    parser.add_argument("--background",    default="Background.png")
    parser.add_argument("--key",           default="certsnkeys/icard_sign.key",
                        help="PEM private key from gen_cert.py")
    parser.add_argument("--output",        default="icard")

    args = parser.parse_args()

    background = Path(args.background)
    image      = Path(args.image)
    key_path   = Path(args.key)

    if not background.is_file():
        parser.error(f"Background not found: {background}")
    if not image.is_file():
        parser.error(f"Photo not found: {image}")
    if not key_path.is_file():
        parser.error(f"Private key not found: {key_path} — run gen_cert.py first")

    # Load private key
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    print(f"Loaded private key: {key_path}")

    # Compress photo to JPEG2000 (60x60, same as UIDAI)
    print(f"Compressing photo: {image}  →  {PHOTO_SZ}x{PHOTO_SZ} JP2")
    photo_jp2 = compress_photo_jp2(str(image))
    print(f"Compressed photo size: {len(photo_jp2)} bytes")

    # Build signed QR payload
    print("Building signed QR payload…")
    qr_decimal = build_qr_payload(args, photo_jp2, key)
    print(f"QR decimal string length: {len(qr_decimal)} digits")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    # Optionally save the extracted photo for inspection
    (output / "embedded_face.jp2").write_bytes(photo_jp2)
    print(f"Embedded face saved: {output}/embedded_face.jp2")

    front = create_front(
        background, args.name, args.dob,
        args.address or f"{args.location}, {args.district}, {args.state} {args.pincode}",
        image,
    )
    back = create_back(background, qr_decimal, args.organisation)

    front_path = output / "icard_front.png"
    back_path  = output / "icard_back.png"

    front.convert("RGB").save(front_path, dpi=(DPI, DPI), optimize=True)
    back.convert("RGB").save(back_path,   dpi=(DPI, DPI), optimize=True)

    print(f"Card size : {CARD_W} x {CARD_H} px @ {DPI} DPI")
    print(f"Front     : {front_path}")
    print(f"Back      : {back_path}")


if __name__ == "__main__":
    main()
