#!/usr/bin/env bash
# Dépose des fichiers dans la release du tag en cours ($GITHUB_REF_NAME) d'un dépôt, en la créant si besoin.
#   publier.sh <propriétaire/dépôt> <fichier>...       (jeton dans GH_TOKEN)
set -euo pipefail
depot="$1"
shift
# Les jobs Windows et Linux publient en parallèle : la release peut être créée par l'autre entre-temps.
gh release view "$GITHUB_REF_NAME" --repo "$depot" > /dev/null 2>&1 \
  || gh release create "$GITHUB_REF_NAME" --repo "$depot" --title "${GITHUB_REF_NAME#v}" --notes "" \
  || gh release view "$GITHUB_REF_NAME" --repo "$depot" > /dev/null
gh release upload "$GITHUB_REF_NAME" "$@" --repo "$depot" --clobber
