# Mattermost Enterprise: keyswap

`keyswap` patch method: it swaps the RSA public key embedded in the Mattermost binary with a key pair you control. The binary then validates licenses against your public key, and the server accepts only licenses signed with the matching private key.

> Use the same keypair for both patching and signing. If you lose or change it, you must re-patch the binary and re-sign the license.

## Prerequisites

- Docker
- `openssl`
- `python3` (optional, only needed to generate new license IDs)
- The files in this repo: `keyswap.Dockerfile`, `patch.sh`, `sign-license.sh`, and `license.json`

## 1) Prepare the keyswap private key

The Dockerfile pulls the official Mattermost enterprise image, extracts its binary, and patches it during the image build. Create the private key that the build will use:

```bash
openssl genrsa -out keyswap-key.pem 2048
chmod 600 keyswap-key.pem
```

Keep `keyswap-key.pem` next to the Dockerfile and signing scripts. It is your private key and must never be committed or exposed.

## 2) Prepare the license JSON

Edit the sample license at [`license.json`](license.json) and update the values for `id` and `customer.id`.

Rules:

- both values must be exactly 26 characters
- only lowercase letters and digits are allowed: `[a-z0-9]`
- the server rejects empty or invalid IDs

Generate a new random ID if needed:

```bash
python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(26)))"
```

## 3) Sign the license with your private key

```bash
./sign-license.sh -o COMPANY-license.mattermost-license license.json
```

This writes a signed Mattermost license bundle in the format expected by the patched binary.

## 4) Build your custom Docker image

Use `keyswap.Dockerfile` to patch a clean Mattermost image during build. The private key is used only in the temporary patcher stage and is not copied into the final image.

Build it:

```bash
docker build -t registry.company.com/mattermost/mattermost-enterprise-edition-patched:12.1.0 -f keyswap.Dockerfile .
```

## 5) Deploy and upload the license

Run your Mattermost container and upload the signed license in the System Console or via `mmctl`.

Example:

```bash
mmctl --local license upload ./COMPANY-license.mattermost-license
```

## Important operational notes

- `keyswap-key.pem` must stay the same for both patching and signing.
- If the key is corrupted or lost, generate a new one with `openssl genrsa -out keyswap-key.pem 2048`, rebuild the image, and re-sign the license.
- Never include the private key in the final production image. Only the public key is embedded in the patched binary.
- Official Mattermost licenses will be rejected by a keyswap-patched binary.
- If the license is signed with a different key than the one embedded in the patched binary, Mattermost will reject it even if the JSON is valid.

## Sources

For broader explanation and compatibility details, see the main project guide in [README.md](README.md).
