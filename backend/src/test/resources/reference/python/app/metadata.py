# Piège : les noms d'empreintes sont des clés de dictionnaire, pas des appels.
def describe(release):
    return {"sha1": release["sha1"], "md5": release.get("md5")}
