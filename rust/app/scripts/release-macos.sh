#!/usr/bin/env bash
# Build signé Developer ID + notarisé de PatchProbe pour macOS (.app et .dmg).
#
# Identifiants lus dans l'environnement ou dans `.env` à la racine du dépôt (git-ignoré, voir
# `.env.example`). Rien n'est écrit sur disque en dehors de `rust/target/`.
#
# À lancer depuis Terminal.app : la notarisation a besoin d'une session utilisateur normale.
set -euo pipefail

app_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$app_dir/../.." && pwd)"
bundle_dir="$app_dir/../target/release/bundle"

if [[ -f "$repo_root/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$repo_root/.env"
  set +a
fi

fail() { echo "erreur : $*" >&2; exit 1; }

[[ "${APPLE_SIGNING_IDENTITY:-}" == "Developer ID Application:"* ]] ||
  fail "APPLE_SIGNING_IDENTITY doit être un certificat « Developer ID Application: … »."
security find-identity -v -p codesigning | grep -qF "\"$APPLE_SIGNING_IDENTITY\"" ||
  fail "certificat introuvable dans le trousseau : $APPLE_SIGNING_IDENTITY"

if [[ -n "${APPLE_API_ISSUER:-}" || -n "${APPLE_API_KEY:-}" ]]; then
  [[ -n "${APPLE_API_ISSUER:-}" && -n "${APPLE_API_KEY:-}" && -f "${APPLE_API_KEY_PATH:-}" ]] ||
    fail "clé App Store Connect incomplète : APPLE_API_ISSUER, APPLE_API_KEY et APPLE_API_KEY_PATH (.p8)."
elif [[ -z "${APPLE_ID:-}" || -z "${APPLE_PASSWORD:-}" || -z "${APPLE_TEAM_ID:-}" ]]; then
  fail "identifiants de notarisation manquants (clé API App Store Connect, ou APPLE_ID/APPLE_PASSWORD/APPLE_TEAM_ID)."
fi

# Volumes laissés par un bundle_dmg.sh interrompu : ils font échouer l'éjection suivante.
for volume in /Volumes/dmg.*; do
  [[ -d "$volume" ]] && hdiutil detach "$volume" -force >/dev/null 2>&1 || true
done

cd "$app_dir"
npm ci
npm run tauri build -- --bundles app,dmg

app="$bundle_dir/macos/PatchProbe.app"
dmg="$(ls -t "$bundle_dir"/dmg/PatchProbe_*.dmg | head -n 1)"

echo "--- vérifications"
codesign --verify --strict --deep "$app"
spctl --assess --type execute -vv "$app"
xcrun stapler validate "$app"
echo "OK : $dmg"
