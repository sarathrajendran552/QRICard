# QRICard

A demonstration of cryptographically signed identity cards using a UIDAI Aadhaar-style QR code format.

Each card embeds a signed QR code on the back that contains all cardholder details and a compressed face photo, protected by an RSA-2048 / SHA-256 digital signature. Any tampering with the card data — or any attempt to create a card without the secret signing key — is detected instantly on verification.

---

## How it works

```
┌─────────────────────────────────────────────────────────┐
│                      Card Issuer                        │
│                                                         │
│   gen_cert.py  →  icard_sign.key  (SECRET — never share)│
│                   icard_sign.cer  (PUBLIC — share freely)│
│                                                         │
│   make_icard.py + icard_sign.key  →  icard_back.png    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                      Card Verifier                      │
│                                                         │
│   qricardreader.py + icard_sign.cer + icard_back.png   │
│   → ✓ VALID  or  ✗ INVALID                             │
└─────────────────────────────────────────────────────────┘
```

The QR payload structure mirrors the Aadhaar Secure QR v2 format:

```
gzip(
  V5 | flag | ref_id | name | dob | gender | address fields...
  | <JPEG2000 face photo bytes>
  | <256-byte RSA-SHA256 signature>
) → big integer → decimal string → QR numeric mode
```

The signature covers every field and the embedded photo. The masked email is appended outside the signed region, identical to UIDAI's design.

---

## Repository contents

| File | Purpose |
|---|---|
| `gen_cert.py` | Generate RSA-2048 private key + self-signed X.509 certificate |
| `make_icard.py` | Generate a signed CR-80 I-Card (front + back PNG) |
| `icardforger.py` | Tamper with the name field to produce a forged card |
| `Background.png` | Card background image |
| `SampleFace.jpg` | Sample face photo for testing |
| `certsnkeys/` | Store your generated key and cert here |
| `icard/` | Output directory for generated cards |

---

## Setup

```bash
uv sync
# or
pip install zxing-cpp pillow opencv-python cryptography qrcode glymur
```

> **OpenJPEG** is required by glymur for JPEG2000 encoding:
> ```bash
> sudo apt install libopenjp2-7        # Debian / Kali
> sudo pacman -S openjpeg2             # Arch
> ```

---

## Demonstration walkthrough

### Step 1 — Generate a certificate and private key

```bash
python3 gen_cert.py \
  --org "My Organisation" \
  --cn  "DS MYORG 01" \
  --key-out certsnkeys/icard_sign.key \
  --cer-out certsnkeys/icard_sign.cer
```

This produces:
- `certsnkeys/icard_sign.key` — the **secret signing key**. Never share or commit this.
- `certsnkeys/icard_sign.cer` — the **public certificate**. Distribute this to verifiers.

---

### Step 2 — Create a valid I-Card

```bash
python3 make_icard.py \
  --name         "John Doe" \
  --dob          "01-01-1990" \
  --gender       M \
  --image        SampleFace.jpg \
  --care-of      "C/O: Jane Doe" \
  --house        "12A" \
  --location     "MG Road" \
  --district     "Bengaluru Urban" \
  --state        "Karnataka" \
  --pincode      "560001" \
  --post-office  "MG Road PO" \
  --vtc          "Bengaluru" \
  --po           "Bengaluru" \
  --mobile-last4 "1234" \
  --id-last4     "5678" \
  --email-masked "jXXXX@gXXXX.com" \
  --organisation "My Organisation" \
  --key          certsnkeys/icard_sign.key
```

Outputs: `icard/icard_front.png` and `icard/icard_back.png`

---

### Step 3 — Copy card and certificate to the reader

```bash
cp icard/icard_back.png    ../QRICardReader/icard_back.png
cp certsnkeys/icard_sign.cer  ../QRICardReader/icard_sign.cer
```

---

### Step 4 — Scan and verify the real card

Run in the QRICardReader repo:
```bash
python3 qricardreader.py --image icard_back.png --cert icard_sign.cer
```
Expected result: **✓ VALID — card details are authentic and untampered**

---

### Step 5 — Forge the I-Card

```bash
python3 icardforger.py \
  --image icard/icard_back.png \
  --name  "FORGED_NAME"
```

Output: `forgedIcard.png` — visually identical card with the name changed, but the original RSA signature is unchanged and now covers different data.

---

### Step 6 — Scan the forged card

```bash
cp forgedIcard.png ../QRICardReader/forgedIcard.png
```

Run in the QRICardReader repo:
```bash
python3 qricardreader.py --image forgedIcard.png --cert icard_sign.cer
```
Expected result: **✗ INVALID — card may be forged or tampered**

The name field reads "FORGED_NAME" but the signature does not match — proving the tampering is detected.

---

### Step 7 — Generate a completely new key pair

```bash
python3 gen_cert.py \
  --org     "Rogue Organisation" \
  --cn      "DS ROGUE 01" \
  --key-out certsnkeys/rogue_sign.key \
  --cer-out certsnkeys/rogue_sign.cer
```

---

### Step 8 — Create a card signed with the new (rogue) key

```bash
python3 make_icard.py \
  --name         "John Doe" \
  --dob          "01-01-1990" \
  --gender       M \
  --image        SampleFace.jpg \
  --organisation "My Organisation" \
  --key          certsnkeys/rogue_sign.key \
  --output       icard_rogue
```

---

### Step 9 — Copy only the card, not the rogue cert

```bash
cp icard_rogue/icard_back.png ../QRICardReader/rogue_back.png
# Do NOT copy rogue_sign.cer
```

---

### Step 10 — Scan the rogue card against the original cert

Run in the QRICardReader repo:
```bash
python3 qricardreader.py --image rogue_back.png --cert icard_sign.cer
```
Expected result: **✗ INVALID**

The card was signed with `rogue_sign.key` but verified against `icard_sign.cer` (which contains the public key for the original key pair). The signature does not match — proving **a card cannot be created without the secret key that corresponds to the trusted certificate**.

---

## Security properties

| Attack | Detected? | Why |
|---|---|---|
| Change any field (name, DOB, address) | ✓ Yes | SHA-256 of signed region changes |
| Swap in a different photo | ✓ Yes | Photo bytes are inside signed region |
| Sign with a different private key | ✓ Yes | Public key in cert won't verify the signature |
| Reuse another card's QR | ✓ Yes | Ref ID and timestamp are signed |
| Tamper with masked email | ✗ No | Email is outside signed region by design (same as UIDAI) |

---

## Notes

- The private key must **never** be committed to version control. It is listed in `.gitignore`.
- The certificate can be freely distributed — it contains only the public key.
- This is a proof-of-concept. For production use, consider: hardware security modules (HSMs) for key storage, certificate chains with a CA, and certificate revocation (CRL/OCSP).
