"""Renseigne la description de la release publiee, a partir du message du commit de la version.

Sans cela les pages de release sont vides : or ce sont elles que les moteurs de recherche indexent en premier,
puisque ce sont les seules pages publiques du produit. On y met donc ce que fait l'outil, ce que contient la
version, et de quoi choisir son fichier.

Appel : python .github/scripts/notes-de-version.py <version sans v> <depot proprietaire/nom> <jeton>
"""
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

PRESENTATION = """**Chiffrium** fait l'inventaire de la cryptographie d'un projet - algorithmes, cles, certificats,
protocoles - a partir d'un depot Git ou d'un dossier local, et produit un **CBOM au format CycloneDX 1.6**.

Chaque element est confronte a une politique (recommande, acceptable, deprecie, interdit) et situe par rapport
au **post-quantique**. L'outil releve aussi les erreurs classiques : secret ecrit en dur, validation TLS
desactivee, alea previsible, derivation de cle trop faible. Export **SARIF** pour GitHub, GitLab, Azure DevOps
et SonarQube.

Tout tourne sur votre machine : votre code n'est envoye nulle part.
"""

ANGLAIS = """*Cryptographic inventory (CBOM) and post-quantum readiness for Git repositories and local folders.
Generates a CycloneDX 1.6 CBOM, evaluates each asset against a policy, and exports SARIF.*
"""


def section():
    """Le message du commit de la version, sans le numero qui l'ouvre ("v1.2.3 : ...")."""
    # Le workflow de release tourne sur le commit du tag : HEAD est la version publiee.
    message = subprocess.run(["git", "log", "-1", "--format=%s", "HEAD"], capture_output=True,
                             text=True, encoding="utf-8").stdout.strip()
    texte = re.sub(r"^v?\d+\.\d+\.\d+\s*:\s*", "", message)
    return texte[:1].upper() + texte[1:] + ("" if texte.endswith(".") or not texte else ".")


def telechargement(version):
    return (f"| Systeme | Fichier |\n|---|---|\n"
            f"| Windows 10/11 (64 bits) | `Chiffrium-Setup-{version}.exe` |\n"
            f"| Linux (Debian, Ubuntu) | `chiffrium-desktop_{version}_amd64.deb` |\n"
            f"| Linux (toute distribution) | `Chiffrium-{version}.AppImage` |\n\n"
            "Java et cdxgen sont fournis avec l'application : rien d'autre a installer.")


def numero(tag):
    """(1, 0, 2) pour "v1.0.2" ; None si le tag n'est pas un numero de version."""
    trouve = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    return tuple(int(n) for n in trouve.groups()) if trouve else None


def appel(methode, url, jeton, corps=None):
    requete = urllib.request.Request(url, method=methode,
                                     data=json.dumps(corps).encode("utf-8") if corps else None)
    requete.add_header("Authorization", f"Bearer {jeton}")
    requete.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(requete) as reponse:
        return json.loads(reponse.read())


def main():
    version, depot, jeton = sys.argv[1], sys.argv[2], sys.argv[3]
    nouveautes = section()
    corps = "\n\n".join(filter(None, [
        PRESENTATION,
        "### Telechargement\n\n" + telechargement(version),
        ("### Cette version\n\n" + nouveautes) if nouveautes else "",
        "---\n\n" + ANGLAIS,
    ]))
    try:
        release = appel("GET", f"https://api.github.com/repos/{depot}/releases/tags/v{version}", jeton)
        # Sans make_latest, retoucher une ancienne release peut la marquer "Latest" : le lien du README et les
        # mises a jour automatiques (qui lisent /releases/latest) serviraient alors cette ancienne version.
        publiees = appel("GET", f"https://api.github.com/repos/{depot}/releases?per_page=100", jeton)
        autres = [numero(r["tag_name"]) for r in publiees
                  if not r["draft"] and not r["prerelease"] and r["id"] != release["id"]]
        actuelle = numero(version)
        plus_recente = actuelle is not None and all(actuelle > autre for autre in autres if autre is not None)
        appel("PATCH", f"https://api.github.com/repos/{depot}/releases/{release['id']}", jeton,
              {"name": f"Chiffrium {version}", "body": corps,
               "make_latest": "true" if plus_recente else "false"})
        print(f"Notes de version ecrites pour v{version} dans {depot}.")
    except urllib.error.HTTPError as erreur:
        # Une release sans description reste utilisable : on ne fait pas echouer la publication pour cela.
        print(f"::warning::Notes de version non ecrites ({erreur.code}) : {erreur.reason}")


if __name__ == "__main__":
    main()
