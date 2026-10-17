#!/usr/bin/env bash
# Paquet Mac App Store de PatchProbe (.pkg signé, prêt pour Transporter).
#
# Usage : scripts/release-appstore.sh [--upload]
#   --upload  envoie le .pkg à App Store Connect avec la clé API (APPLE_API_KEY…).
#
# Identifiants lus dans l'environnement ou dans `.env` à la racine du dépôt (git-ignoré, voir
# `.env.example`). L'édition App Store tourne dans le bac à sable d'Apple : pas de MAC, de
# traceroute ni de nmap (l'interface le signale). À lancer depuis Terminal.app.
set -euo pipefail

app_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$app_dir/../.." && pwd)"
target_root="$(cd "$app_dir/.." && pwd)/target"
out_dir="$target_root/appstore"
bundle_id="com.patchbay.patchprobe"

upload=false
[[ "${1:-}" == "--upload" ]] && upload=true

if [[ -f "$repo_root/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$repo_root/.env"
  set +a
fi

fail() { echo "erreur : $*" >&2; exit 1; }
has_identity() { security find-identity -v | grep -qF "\"$1\""; }

[[ "${APPLE_DISTRIBUTION_IDENTITY:-}" == "Apple Distribution:"* ||
   "${APPLE_DISTRIBUTION_IDENTITY:-}" == "3rd Party Mac Developer Application:"* ]] ||
  fail "APPLE_DISTRIBUTION_IDENTITY doit être un certificat « Apple Distribution: … »."
[[ "${APPLE_INSTALLER_IDENTITY:-}" == "3rd Party Mac Developer Installer:"* ||
   "${APPLE_INSTALLER_IDENTITY:-}" == "Mac Installer Distribution:"* ]] ||
  fail "APPLE_INSTALLER_IDENTITY doit être un certificat « 3rd Party Mac Developer Installer: … »."
has_identity "$APPLE_DISTRIBUTION_IDENTITY" || fail "certificat introuvable : $APPLE_DISTRIBUTION_IDENTITY"
has_identity "$APPLE_INSTALLER_IDENTITY" || fail "certificat introuvable : $APPLE_INSTALLER_IDENTITY"
[[ -n "${APPLE_TEAM_ID:-}" ]] || fail "APPLE_TEAM_ID manquant."
[[ -f "${APPLE_PROVISIONING_PROFILE:-}" ]] ||
  fail "APPLE_PROVISIONING_PROFILE doit pointer vers le profil « Mac App Store Connect » (.provisionprofile)."

version="$(node -p 'require(process.argv[1]).version' "$app_dir/src-tauri/tauri.conf.json")"
# CFBundleVersion doit croître à chaque envoi : compteur versionné dans `appstore/build-number`,
# à incrémenter avant chaque soumission (BUILD_NUMBER reste prioritaire pour un envoi ponctuel).
build_number="${BUILD_NUMBER:-$(tr -d '[:space:]' < "$app_dir/src-tauri/appstore/build-number")}"
[[ "$build_number" =~ ^[0-9]+$ ]] || fail "numéro de build invalide : « $build_number »."

# Binaire universel si la cible Intel est installée, sinon Apple silicon seulement : l'App Store
# n'accepte alors le paquet qu'avec macOS 12.0 minimum (erreur 90869).
if [[ -d "$(rustc --print target-libdir --target x86_64-apple-darwin 2>/dev/null)" ]]; then
  target="universal-apple-darwin"
  minimum_macos="11.0"
else
  target="aarch64-apple-darwin"
  minimum_macos="12.0"
  echo "note : cible x86_64-apple-darwin absente, paquet Apple silicon uniquement (macOS 12.0+)."
fi

mkdir -p "$out_dir"
sed -e "s/__TEAM_ID__/$APPLE_TEAM_ID/g" -e "s/__BUNDLE_ID__/$bundle_id/g" \
  "$app_dir/src-tauri/appstore/Entitlements.plist.in" > "$out_dir/Entitlements.plist"
node -e '
  const [entitlements, profile, build, minimumSystemVersion, file] = process.argv.slice(1);
  const config = { bundle: { macOS: {
    entitlements, bundleVersion: build, minimumSystemVersion,
    files: { "embedded.provisionprofile": profile },
  } } };
  require("fs").writeFileSync(file, JSON.stringify(config, null, 2));
' "$out_dir/Entitlements.plist" "$APPLE_PROVISIONING_PROFILE" "$build_number" "$minimum_macos" \
  "$out_dir/tauri.appstore.json"

cd "$app_dir"
npm ci
# Variables de notarisation retirées : un paquet App Store n'est pas notarisé.
env -u APPLE_ID -u APPLE_PASSWORD -u APPLE_API_ISSUER -u APPLE_API_KEY -u APPLE_API_KEY_PATH \
  APPLE_SIGNING_IDENTITY="$APPLE_DISTRIBUTION_IDENTITY" \
  npm run tauri build -- --bundles app --target "$target" --config "$out_dir/tauri.appstore.json"

app="$target_root/$target/release/bundle/macos/PatchProbe.app"
pkg="$out_dir/PatchProbe-$version-$build_number.pkg"

echo "--- vérifications"
codesign --verify --strict --deep "$app"
codesign -d --entitlements - --xml "$app" 2>/dev/null | grep -q "com.apple.security.app-sandbox" ||
  fail "le bac à sable n'est pas activé dans la signature."
[[ -f "$app/Contents/embedded.provisionprofile" ]] || fail "profil de provisionnement absent du .app."
[[ "$(plutil -extract LSMinimumSystemVersion raw "$app/Contents/Info.plist")" == "$minimum_macos" ]] ||
  fail "LSMinimumSystemVersion différent de $minimum_macos."

productbuild --component "$app" /Applications --sign "$APPLE_INSTALLER_IDENTITY" "$pkg"
pkgutil --check-signature "$pkg" | head -n 3
echo "OK : $pkg (version $version, build $build_number)"

if $upload; then
  [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_ISSUER:-}" && -f "${APPLE_API_KEY_PATH:-}" ]] ||
    fail "--upload demande APPLE_API_KEY, APPLE_API_ISSUER et APPLE_API_KEY_PATH."
  API_PRIVATE_KEYS_DIR="$(dirname "$APPLE_API_KEY_PATH")" \
    xcrun altool --upload-app -f "$pkg" -t macos --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"
else
  echo "Envoi : glisser le .pkg dans l'app Transporter, ou relancer avec --upload."
fi
