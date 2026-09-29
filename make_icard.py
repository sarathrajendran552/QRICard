#!/usr/bin/env python3
"""
Create a two-sided CR-80 I-Card template.

Expected files in the working directory:
  Background.png

Usage:
  python3 make_icard.py \
      --name "John Doe" \
      --dob "01/01/1990" \
      --address "123 Example Street, Bengaluru" \
      --organisation "Example Organisation" \
      --image "SampleFace.jpg" \
      --output "icard"

Outputs:
  icard_front.png
  icard_back.png

The card is rendered at 300 DPI:
  85.6 x 54.0 mm ~= 1011 x 638 pixels
"""

import argparse
import json
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
import qrcode

DPI = 300
CARD_W = round(85.6 / 25.4 * DPI)
CARD_H = round(54.0 / 25.4 * DPI)


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
    """Cover the CR-80 canvas with the supplied background image."""
    bg = Image.open(path).convert("RGB")
    scale = max(CARD_W / bg.width, CARD_H / bg.height)
    new_size = (math.ceil(bg.width * scale), math.ceil(bg.height * scale))
    bg = bg.resize(new_size, Image.Resampling.LANCZOS)

    left = (bg.width - CARD_W) // 2
    top = (bg.height - CARD_H) // 2
    return bg.crop((left, top, left + CARD_W, top + CARD_H)).convert("RGBA")


def fit_image(image_path, size):
    """Resize/crop a portrait into a fixed rectangle."""
    img = Image.open(image_path).convert("RGB")
    w, h = size
    scale = max(w / img.width, h / img.height)
    new_size = (math.ceil(img.width * scale), math.ceil(img.height * scale))
    img = img.resize(new_size, Image.Resampling.LANCZOS)

    left = (img.width - w) // 2
    top = (img.height - h) // 2
    return img.crop((left, top, left + w, top + h))


def draw_wrapped_text(draw, text, xy, font, fill, max_width, line_spacing=8):
    """Draw wrapped text and return the bottom Y coordinate."""
    words = str(text).split()
    lines = []
    current = ""

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
    bbox = draw.textbbox((x, y), "Ag", font=font)
    line_h = bbox[3] - bbox[1]

    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += line_h + line_spacing

    return y


def create_front(background, name, dob, address, image_path):
    card = fit_background(background)
    draw = ImageDraw.Draw(card)

    margin = 45
    picture_w = 275
    picture_h = 345
    picture_x = margin
    picture_y = 135

    # Portrait with a subtle border.
    portrait = fit_image(image_path, (picture_w, picture_h))
    card.paste(portrait, (picture_x, picture_y))
    draw.rectangle(
        [picture_x, picture_y, picture_x + picture_w, picture_y + picture_h],
        outline="white",
        width=5,
    )

    title_font = load_font(48, bold=True)
    label_font = load_font(27, bold=True)
    value_font = load_font(27)
    address_font = load_font(24)

    # Semi-transparent information panel.
    panel_x = 355
    panel_y = 125
    panel_w = CARD_W - panel_x - margin
    panel_h = CARD_H - panel_y - 45

    overlay = Image.new("RGBA", card.size, (0, 0, 0, 0))
    odraw = ImageDraw.Draw(overlay)
    odraw.rounded_rectangle(
        [panel_x, panel_y, panel_x + panel_w, panel_y + panel_h],
        radius=22,
        fill=(0, 0, 0, 135),
    )
    card = Image.alpha_composite(card, overlay)
    draw = ImageDraw.Draw(card)

    x = panel_x + 25
    y = panel_y + 25

    # Name
    name_text = str(name)
    # Shrink very long names to fit the panel.
    f = title_font
    while draw.textbbox((0, 0), name_text, font=f)[2] > panel_w - 50 and f.size > 25:
        f = load_font(f.size - 2, bold=True)
    draw.text((x, y), name_text, font=f, fill="white")
    y += f.size + 30

    draw.text((x, y), "DOB", font=label_font, fill="white")
    y += 34
    y = draw_wrapped_text(
        draw, dob, (x, y), value_font, "white", panel_w - 50, line_spacing=4
    )
    y += 12

    draw.text((x, y), "ADDRESS", font=label_font, fill="white")
    y += 34
    draw_wrapped_text(
        draw, address, (x, y), address_font, "white", panel_w - 50, line_spacing=5
    )

    return card


def create_back(background, details, organisation):
    card = fit_background(background)
    draw = ImageDraw.Draw(card)

    qr_payload = json.dumps(details, ensure_ascii=False, separators=(",", ":"))

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=2,
    )
    qr.add_data(qr_payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    max_qr = min(CARD_H - 180, CARD_W - 180)
    qr_img.thumbnail((max_qr, max_qr), Image.Resampling.LANCZOS)

    qr_x = (CARD_W - qr_img.width) // 2
    qr_y = 70

    # White QR plate for reliable scanning over arbitrary backgrounds.
    pad = 22
    plate = Image.new("RGBA", (qr_img.width + 2 * pad, qr_img.height + 2 * pad), "white")
    card.alpha_composite(plate, (qr_x - pad, qr_y - pad))
    card.paste(qr_img, (qr_x, qr_y))

    org_font = load_font(42, bold=True)
    small_font = load_font(21)

    # Organisation below the QR code.
    org_text = str(organisation)
    max_width = CARD_W - 80
    while draw.textbbox((0, 0), org_text, font=org_font)[2] > max_width and org_font.size > 22:
        org_font = load_font(org_font.size - 2, bold=True)

    bbox = draw.textbbox((0, 0), org_text, font=org_font)
    org_x = (CARD_W - (bbox[2] - bbox[0])) // 2
    org_y = qr_y + qr_img.height + 45
    draw.text((org_x, org_y), org_text, font=org_font, fill="white")

    # Small machine-readable note.
    note = ""
    nb = draw.textbbox((0, 0), note, font=small_font)
    draw.text(
        ((CARD_W - (nb[2] - nb[0])) // 2, CARD_H - 45),
        note,
        font=small_font,
        fill="white",
    )

    return card


def main():
    parser = argparse.ArgumentParser(description="Create a two-sided CR-80 I-Card.")
    parser.add_argument("--name", required=True)
    parser.add_argument("--dob", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--organisation", required=True)
    parser.add_argument("--image", required=True, help="Path to the person's photo")
    parser.add_argument("--background", default="Background.png")
    parser.add_argument("--output", default="icard")
    args = parser.parse_args()

    background = Path(args.background)
    image = Path(args.image)

    if not background.is_file():
        parser.error(f"Background not found: {background}")
    if not image.is_file():
        parser.error(f"Photo not found: {image}")

    details = {
        "name": args.name,
        "dob": args.dob,
        "address": args.address,
        "organisation": args.organisation,
    }

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    front = create_front(
        background, args.name, args.dob, args.address, image
    )
    back = create_back(background, details, args.organisation)

    front_path = output / "icard_front.png"
    back_path = output / "icard_back.png"

    front.convert("RGB").save(front_path, dpi=(DPI, DPI), optimize=True)
    back.convert("RGB").save(back_path, dpi=(DPI, DPI), optimize=True)

    print(f"Card size: {CARD_W} x {CARD_H} px @ {DPI} DPI")
    print(f"Front: {front_path}")
    print(f"Back : {back_path}")


if __name__ == "__main__":
    main()
