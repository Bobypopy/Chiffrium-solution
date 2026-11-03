// Règles de détection : titres, explications et corrections attendues.
// Source : backend/src/main/resources/findings/*.json. Ajouter une règle impose d'ajouter sa traduction ici
// (le test frontend/tests/i18n.test.mjs échoue sinon).

export const REGLES = {
  // --- Secrets exposés
  'Secret en dur': 'Hardcoded secret',
  'Mot de passe, jeton ou clé d\'API affecté à une valeur littérale.':
    'A password, token or API key assigned a literal value.',
  'Secret dans un fichier de configuration': 'Secret in a configuration file',
  'Mot de passe ou jeton en clair dans la configuration.':
    'A password or token in clear text in the configuration.',
  'Identifiants dans une URL': 'Credentials in a URL',
  'URL contenant un identifiant et un mot de passe.': 'A URL containing a username and a password.',
  'Clé d\'accès AWS': 'AWS access key',
  'Identifiant de clé d\'accès AWS en clair.': 'AWS access key identifier in clear text.',
  'Clé secrète AWS': 'AWS secret key',
  'Clé secrète AWS en clair : accès complet au compte associé.':
    'AWS secret key in clear text: full access to the account it belongs to.',
  'Jeton GitHub': 'GitHub token',
  'Jeton d\'accès GitHub en clair.': 'GitHub access token in clear text.',
  'Jeton GitLab': 'GitLab token',
  'Jeton d\'accès personnel GitLab en clair.': 'GitLab personal access token in clear text.',
  'Jeton npm': 'npm token',
  'Jeton de publication npm en clair (risque de compromission de la chaîne d\'approvisionnement).':
    'npm publishing token in clear text (supply-chain compromise risk).',
  'Jeton ou webhook Slack': 'Slack token or webhook',
  'Jeton Slack ou URL de webhook en clair.': 'Slack token or webhook URL in clear text.',
  'Clé secrète Stripe': 'Stripe secret key',
  'Clé secrète de production Stripe en clair.': 'Stripe live secret key in clear text.',
  'Clé d\'API Google': 'Google API key',
  'Clé d\'API Google Cloud en clair.': 'Google Cloud API key in clear text.',
  'Clé de stockage Azure': 'Azure storage key',
  'Chaîne de connexion Azure Storage contenant la clé du compte.':
    'Azure Storage connection string containing the account key.',
  'Clé d\'API d\'IA': 'AI provider API key',
  'Clé d\'API d\'un fournisseur d\'IA (OpenAI, Anthropic...) en clair.':
    'API key of an AI provider (OpenAI, Anthropic...) in clear text.',
  'Jeton JWT en dur': 'Hardcoded JWT',
  'Jeton JWT complet écrit dans le code : il peut donner un accès tant qu\'il n\'a pas expiré.':
    'A complete JWT written in the code: it can grant access until it expires.',
  'Fichier .env versionné': '.env file committed',
  'Fichier d\'environnement versionné : il contient souvent des secrets.':
    'Environment file committed to the repository: it often holds secrets.',
  ['Révoquer puis régénérer ce secret immédiatement (il reste dans l\'historique Git), puis le lire depuis '
    + 'un coffre (Vault, secret Kubernetes, variable d\'environnement).']:
    'Revoke and reissue this secret at once (it stays in the Git history), then read it from a vault '
    + '(Vault, Kubernetes secret, environment variable).',
  'Supprimer le jeton du code et en émettre un nouveau à l\'exécution.':
    'Remove the token from the code and issue a new one at runtime.',
  'Ajouter le fichier au .gitignore et fournir un modèle .env.example sans valeur réelle.':
    'Add the file to .gitignore and ship a .env.example template with no real value.',
  'Retirer le fichier du dépôt (et de l\'historique), le fournir au déploiement depuis un coffre.':
    'Remove the file from the repository (and from its history), and supply it at deployment from a vault.',

  // --- Clés et matériel cryptographique
  'Clé privée en clair': 'Unencrypted private key',
  'Clé privée non chiffrée présente dans le dépôt.':
    'An unencrypted private key is present in the repository.',
  'Clé privée chiffrée versionnée': 'Encrypted private key committed',
  'Clé privée protégée par mot de passe présente dans le dépôt (attaque hors ligne possible).':
    'A password-protected private key is present in the repository (offline attack possible).',
  'Magasin de clés versionné': 'Keystore committed',
  'Fichier PKCS#12 / JKS versionné : les clés qu\'il contient sont exposées à quiconque lit le dépôt.':
    'PKCS#12 / JKS file committed: the keys it holds are exposed to anyone who reads the repository.',
  ['Retirer la clé du dépôt, la considérer comme compromise, la régénérer et la stocker dans un coffre ou '
    + 'un HSM.']:
    'Remove the key from the repository, treat it as compromised, regenerate it and store it in a vault or '
    + 'an HSM.',
  'Stocker la clé hors du dépôt (coffre, HSM) et vérifier la robustesse de sa phrase de passe.':
    'Store the key outside the repository (vault, HSM) and check that its passphrase is strong.',
  'Clé privée encodée en Base64': 'Base64-encoded private key',
  ['Clé privée PEM encodée en Base64 (Secret Kubernetes, kubeconfig, valeurs Helm) : l\'encodage ne la protège '
    + 'pas, quiconque lit le dépôt la décode.']:
    'PEM private key encoded in Base64 (Kubernetes Secret, kubeconfig, Helm values): the encoding does not '
    + 'protect it, anyone who reads the repository can decode it.',
  'Clé privée JWK en clair': 'Plaintext JWK private key',
  ['Clé JWK privée ou secrète (champ "d" ou "k") présente dans le dépôt : elle permet de signer ou de déchiffrer '
    + 'à la place de son propriétaire.']:
    'Private or secret JWK (field "d" or "k") present in the repository: it lets anyone sign or decrypt in '
    + 'place of its owner.',
  'État Terraform versionné': 'Terraform state committed',
  ['L\'état Terraform contient en clair les secrets des ressources gérées : clés privées de tls_private_key, '
    + 'mots de passe de bases de données, jetons.']:
    'The Terraform state holds the secrets of the managed resources in clear text: tls_private_key private '
    + 'keys, database passwords, tokens.',
  ['Retirer le fichier du dépôt (et de l\'historique), stocker l\'état dans un backend distant chiffré (S3 avec '
    + 'KMS, Terraform Cloud...) et renouveler les secrets qu\'il contient.']:
    'Remove the file from the repository (and from its history), keep the state in an encrypted remote '
    + 'backend (S3 with KMS, Terraform Cloud...) and renew the secrets it holds.',
  'Clé privée exportée sans chiffrement': 'Private key exported without encryption',
  ['La clé privée est écrite en clair : sur le disque ou en transit, elle n\'est protégée par rien d\'autre '
    + 'que les droits du fichier.']:
    'The private key is written in clear text: on disk or in transit, nothing but the file permissions '
    + 'protects it.',
  ['Chiffrer la clé à l\'export (PKCS#8 chiffré par une phrase de passe forte) ou la garder dans un magasin '
    + 'protégé (keystore, trousseau du système, HSM, KMS).']:
    'Encrypt the key when exporting it (PKCS#8 encrypted with a strong passphrase) or keep it in a protected '
    + 'store (keystore, system keyring, HSM, KMS).',
  'Mot de passe de clé ou de magasin de clés en dur': 'Hardcoded key or keystore password',
  ['Le mot de passe qui protège la clé ou le magasin est écrit dans le code : il ne protège plus rien pour '
    + 'qui lit le dépôt.']:
    'The password protecting the key or the keystore is written in the code: it protects nothing from '
    + 'anyone who reads the repository.',
  ['Lire le mot de passe dans un coffre ou une variable d\'environnement au déploiement, et changer celui du '
    + 'magasin existant.']:
    'Read the password from a vault or an environment variable at deployment, and change the one of the '
    + 'existing keystore.',
  'Clé symétrique en dur': 'Hardcoded symmetric key',
  'Clé symétrique en dur (constante)': 'Hardcoded symmetric key (constant)',
  'Clé de chiffrement littérale passée au chiffreur.': 'A literal encryption key passed to the cipher.',
  'Clé de chiffrement construite à partir d\'une constante du code.':
    'An encryption key built from a constant in the code.',
  'Clé littérale passée à aes.NewCipher.': 'A literal key passed to aes.NewCipher.',
  'Clé littérale passée à createCipheriv.': 'A literal key passed to createCipheriv.',
  'Clé littérale passée à openssl_encrypt/openssl_decrypt.':
    'A literal key passed to openssl_encrypt/openssl_decrypt.',
  ['La clé vient d\'une constante du fichier : elle est dans le dépôt et dans le binaire livré, donc connue '
    + 'de quiconque y a accès.']:
    'The key comes from a constant in the file: it is in the repository and in the shipped binary, so known '
    + 'to anyone with access.',
  'La clé vient d\'une constante du module : elle est dans le dépôt, donc connue de quiconque y a accès.':
    'The key comes from a constant in the module: it is in the repository, so known to anyone with access.',
  'La clé vient d\'une constante du module : elle est dans le dépôt et dans le paquet publié.':
    'The key comes from a constant in the module: it is in the repository and in the published package.',
  'La clé vient d\'une constante de la classe : elle est dans le dépôt et dans l\'assembly livré.':
    'The key comes from a constant in the class: it is in the repository and in the shipped assembly.',
  ['Générer la clé aléatoirement ou la dériver (KDF) et la stocker dans un coffre ; ne jamais l\'écrire dans '
    + 'le code.']:
    'Generate the key at random or derive it (KDF) and store it in a vault; never write it in the code.',
  ['Générer la clé aléatoirement ou la dériver d\'un secret (KDF), et la stocker dans un coffre ou une '
    + 'variable d\'environnement.']:
    'Generate the key at random or derive it from a secret (KDF), and store it in a vault or an environment '
    + 'variable.',
  ['Générer la clé aléatoirement ou la dériver d\'un secret (KDF), et la lire dans l\'environnement ou un '
    + 'coffre.']:
    'Generate the key at random or derive it from a secret (KDF), and read it from the environment or a '
    + 'vault.',
  ['Générer la clé aléatoirement ou la dériver d\'un secret (KDF), et la stocker dans un coffre (DPAPI, Key '
    + 'Vault).']:
    'Generate the key at random or derive it from a secret (KDF), and store it in a vault (DPAPI, Key '
    + 'Vault).',
  'Clé ou IV en dur': 'Hardcoded key or IV',
  'Clé ou IV défini à partir d\'une constante.': 'A key or IV set from a constant.',
  'IV ou nonce constant': 'Constant IV or nonce',
  'IV/nonce constant ou nul : même chiffré pour un même message, et en GCM perte totale de sécurité.':
    'Constant or zero IV/nonce: the same message always gives the same ciphertext, and in GCM security is '
    + 'lost entirely.',
  'IV/nonce littéral.': 'Literal IV/nonce.',
  'IV littéral ou nul (Buffer.alloc) passé à createCipheriv.':
    'Literal or zero IV (Buffer.alloc) passed to createCipheriv.',
  ['Générer un IV/nonce aléatoire et unique à chaque chiffrement (et le transmettre avec le chiffré) ; en '
    + 'GCM, ne jamais réutiliser un nonce avec la même clé.']:
    'Generate a random, unique IV/nonce for every encryption (and send it with the ciphertext); in GCM, '
    + 'never reuse a nonce with the same key.',

  // --- Dérivation de clé
  'Dérivation de clé faible': 'Weak key derivation',
  'PBKDF2 : itérations insuffisantes': 'PBKDF2: not enough iterations',
  'Nombre d\'itérations trop faible face aux attaques par force brute sur GPU.':
    'Iteration count too low against GPU brute-force attacks.',
  'Dérivation de clé : paramètre trop faible dans la configuration':
    'Key derivation: parameter too weak in the configuration',
  ['Le nombre d\'itérations configuré est trop bas face aux attaques par force brute sur GPU ; un mot de '
    + 'passe dérivé avec ce réglage se retrouve vite.']:
    'The configured iteration count is too low against GPU brute-force attacks; a password derived with '
    + 'this setting is recovered quickly.',
  'bcrypt : coût trop faible': 'bcrypt: cost too low',
  'Facteur de coût bcrypt inférieur à 10.': 'bcrypt cost factor below 10.',
  'Sel constant': 'Constant salt',
  'Sel de dérivation constant : les mêmes mots de passe donnent les mêmes clés (attaques par tables).':
    'Constant derivation salt: the same passwords give the same keys (table attacks).',
  ['Utiliser Argon2id (ou scrypt), ou PBKDF2 avec au moins 600 000 itérations (HMAC-SHA256) / 210 000 '
    + '(HMAC-SHA512) selon l\'OWASP.']:
    'Use Argon2id (or scrypt), or PBKDF2 with at least 600,000 iterations (HMAC-SHA256) / 210,000 '
    + '(HMAC-SHA512) as OWASP recommends.',
  ['Argon2id de préférence ; sinon PBKDF2 avec au moins 600 000 itérations (HMAC-SHA256) ou 210 000 '
    + '(HMAC-SHA512), selon l\'OWASP.']:
    'Argon2id for preference; otherwise PBKDF2 with at least 600,000 iterations (HMAC-SHA256) or 210,000 '
    + '(HMAC-SHA512), as OWASP recommends.',
  'Utiliser un coût d\'au moins 10 (12 recommandé), ou Argon2id.':
    'Use a cost of at least 10 (12 recommended), or Argon2id.',
  'Générer un sel aléatoire d\'au moins 16 octets par mot de passe et le stocker avec l\'empreinte.':
    'Generate a random salt of at least 16 bytes per password and store it alongside the hash.',

  // --- Aléa
  'Aléa non cryptographique pour un secret': 'Non-cryptographic randomness for a secret',
  'Math.random pour un secret': 'Math.random for a secret',
  'Math.random n\'est pas un générateur cryptographique.': 'Math.random is not a cryptographic generator.',
  'Générateur non cryptographique': 'Non-cryptographic generator',
  // --- PowerShell
  'Get-Random pour un secret': 'Get-Random for a secret',
  'Get-Random et System.Random ne sont pas des générateurs cryptographiques.':
    'Get-Random and System.Random are not cryptographic generators.',
  'Mot de passe en clair dans un script': 'Plaintext password in a script',
  'ConvertTo-SecureString -AsPlainText reçoit le mot de passe écrit dans le script : il est lisible par quiconque lit le dépôt.':
    'ConvertTo-SecureString -AsPlainText receives the password written in the script: anyone who reads the repository can read it.',
  'Demander le mot de passe (Read-Host -AsSecureString, Get-Credential) ou le lire dans un coffre (SecretManagement, Azure Key Vault).':
    'Prompt for the password (Read-Host -AsSecureString, Get-Credential) or read it from a vault (SecretManagement, Azure Key Vault).',
  'Validation du certificat désactivée (PowerShell)': 'Certificate validation disabled (PowerShell)',
  "Tous les certificats sont acceptés : une attaque de l'homme du milieu devient triviale.":
    'Every certificate is accepted: a man-in-the-middle attack becomes trivial.',
  'Clé ou IV en dur': 'Hard-coded key or IV',
  'Clé de chiffrement ou IV écrit dans le script (octets ou Base64) : quiconque lit le dépôt peut déchiffrer.':
    'Encryption key or IV written in the script (bytes or Base64): anyone who reads the repository can decrypt.',
  'Générateur prévisible : aucun usage sensible n\'est visible sur la ligne, vérifier qu\'il ne produit ni secret, ni jeton, ni identifiant.':
    'Predictable generator: no sensitive use is visible on the line; check that it produces no secret, token or identifier.',
  'Module random pour un secret': 'random module for a secret',
  'Le module random (Mersenne Twister) est prévisible.':
    'The random module (Mersenne Twister) is predictable.',
  'System.Random pour un secret': 'System.Random for a secret',
  'System.Random est prévisible.': 'System.Random is predictable.',
  'rand pour un secret': 'rand for a secret',
  'rand() pour un secret': 'rand() for a secret',
  'rand/mt_rand/uniqid pour un secret': 'rand/mt_rand/uniqid for a secret',
  'rand, mt_rand, uniqid et str_shuffle sont prévisibles.':
    'rand, mt_rand, uniqid and str_shuffle are predictable.',
  'rand/random/drand48 sont prévisibles.': 'rand, random and drand48 are predictable.',
  'Kernel#rand et Random sont prévisibles.': 'Kernel#rand and Random are predictable.',
  'Random() pour un secret': 'Random() for a secret',
  'Random() sans .secure() est prévisible.': 'Random() without .secure() is predictable.',
  ':rand pour un secret': ':rand for a secret',
  ':rand et Enum.random sont prévisibles.': ':rand and Enum.random are predictable.',
  'rand de Perl est prévisible.': 'Perl rand is predictable.',
  'java.util.Random / Math.random / RandomStringUtils sont prévisibles.':
    'java.util.Random, Math.random and RandomStringUtils are predictable.',
  'math/rand importé': 'math/rand imported',
  'math/rand est prévisible : vérifier qu\'il ne sert pas à produire des secrets.':
    'math/rand is predictable: check that it is not used to produce secrets.',
  'Graine fixe': 'Fixed seed',
  'Générateur initialisé avec une graine constante : toute la suite est reproductible.':
    'Generator seeded with a constant: the whole sequence is reproducible.',
  ['Utiliser le générateur cryptographique du langage (SecureRandom, secrets, '
    + 'crypto.randomBytes/getRandomValues, crypto/rand, RandomNumberGenerator, random_bytes).']:
    'Use the cryptographic generator of the language (SecureRandom, secrets, '
    + 'crypto.randomBytes/getRandomValues, crypto/rand, RandomNumberGenerator, random_bytes).',
  ['Ne jamais fixer la graine d\'un générateur utilisé pour la sécurité (laisser SecureRandom s\'initialiser '
    + 'seul).']:
    'Never seed a generator used for security (let SecureRandom seed itself).',

  // --- Validation TLS
  'Validation TLS désactivée': 'TLS validation disabled',
  'TrustManager qui accepte tout': 'Trust-all TrustManager',
  ['checkServerTrusted vide : désactive la vérification du certificat serveur : une attaque de l\'homme du '
    + 'milieu devient triviale.']:
    'Empty checkServerTrusted: disables server certificate verification, making a man-in-the-middle attack '
    + 'trivial.',
  'Stratégie de confiance permissive': 'Permissive trust strategy',
  ['TrustAllStrategy / InsecureTrustManagerFactory désactive la vérification du certificat serveur : une '
    + 'attaque de l\'homme du milieu devient triviale.']:
    'TrustAllStrategy / InsecureTrustManagerFactory disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'Vérification du nom d\'hôte désactivée': 'Hostname verification disabled',
  'Le nom d\'hôte du certificat n\'est pas vérifié.': 'The certificate hostname is not checked.',
  ['SSLSocket créé directement : Java ne vérifie pas que le certificat correspond au serveur contacté sans '
    + 'setEndpointIdentificationAlgorithm("HTTPS").']:
    'SSLSocket created directly: Java does not check that the certificate matches the server it talks to '
    + 'without setEndpointIdentificationAlgorithm("HTTPS").',
  'verify=False': 'verify=False',
  ['Requête HTTPS sans vérification du certificat : désactive la vérification du certificat serveur : une '
    + 'attaque de l\'homme du milieu devient triviale.']:
    'HTTPS request without certificate verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  ["Requête sans vérification du certificat : désactive la vérification du certificat serveur : "
    + "une attaque de l'homme du milieu devient triviale."]:
    'Request without certificate verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'rejectUnauthorized: false': 'rejectUnauthorized: false',
  ['Connexion TLS Node.js sans vérification : désactive la vérification du certificat serveur : une attaque '
    + 'de l\'homme du milieu devient triviale.']:
    'Node.js TLS connection without verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'NODE_TLS_REJECT_UNAUTHORIZED=0': 'NODE_TLS_REJECT_UNAUTHORIZED=0',
  'Désactive la vérification TLS pour tout le processus Node.js.':
    'Disables TLS verification for the whole Node.js process.',
  'InsecureSkipVerify': 'InsecureSkipVerify',
  ['tls.Config avec InsecureSkipVerify : désactive la vérification du certificat serveur : une attaque de '
    + 'l\'homme du milieu devient triviale.']:
    'tls.Config with InsecureSkipVerify: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'Callback de certificat permissif': 'Permissive certificate callback',
  ['La validation du certificat renvoie toujours vrai : désactive la vérification du certificat serveur : '
    + 'une attaque de l\'homme du milieu devient triviale.']:
    'Certificate validation always returns true: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'Vérification SSL désactivée (PHP)': 'SSL verification disabled (PHP)',
  ['Connexion OpenSSL ou libcurl sans vérification : désactive la vérification du certificat serveur : une '
    + 'attaque de l\'homme du milieu devient triviale.']:
    'OpenSSL or libcurl connection without verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'VERIFY_NONE': 'VERIFY_NONE',
  ['Connexion TLS Ruby sans vérification : désactive la vérification du certificat serveur : une attaque de '
    + 'l\'homme du milieu devient triviale.']:
    'Ruby TLS connection without verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  ['Connexion TLS Erlang/Elixir sans vérification : désactive la vérification du certificat serveur : une '
    + 'attaque de l\'homme du milieu devient triviale.']:
    'Erlang/Elixir TLS connection without verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  ['Connexion TLS Perl sans vérification : désactive la vérification du certificat serveur : une attaque de '
    + 'l\'homme du milieu devient triviale.']:
    'Perl TLS connection without verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'SSL_VERIFY_NONE / VERIFYPEER 0': 'SSL_VERIFY_NONE / VERIFYPEER 0',
  'Contexte SSL non vérifié': 'Unverified SSL context',
  ['Contexte SSL sans vérification : désactive la vérification du certificat serveur : une attaque de '
    + 'l\'homme du milieu devient triviale.']:
    'SSL context without verification: disables server certificate verification, making a '
    + 'man-in-the-middle attack trivial.',
  'Certificats invalides acceptés': 'Invalid certificates accepted',
  'Client HTTP Rust qui accepte les certificats ou noms d\'hôte invalides.':
    'Rust HTTP client accepting invalid certificates or hostnames.',
  'Confiance inconditionnelle (Swift)': 'Unconditional trust (Swift)',
  'Le défi d\'authentification serveur est accepté sans évaluation du certificat.':
    'The server authentication challenge is accepted without evaluating the certificate.',
  'Outil en ligne de commande sans vérification TLS': 'Command-line tool without TLS verification',
  ['curl -k, wget --no-check-certificate ou git sslVerify=false : les téléchargements peuvent être '
    + 'falsifiés.']:
    'curl -k, wget --no-check-certificate or git sslVerify=false: downloads can be tampered with.',
  ['Conserver la validation par défaut ; pour une autorité interne, l\'ajouter au magasin de confiance '
    + 'plutôt que désactiver la vérification.']:
    'Keep the default validation; for an internal authority, add it to the trust store instead of turning '
    + 'verification off.',

  // --- JWT
  'JWT non vérifié': 'Unverified JWT',
  'JWT décodé sans vérification': 'JWT decoded without verification',
  'jwt.decode sans verify': 'jwt.decode without verify',
  'jwt.decode lit les revendications sans vérifier la signature : ne pas s\'en servir pour autoriser.':
    'jwt.decode reads the claims without checking the signature: do not use it to authorise.',
  'JWT non vérifié (Go)': 'Unverified JWT (Go)',
  'ParseUnverified ou UnsafeAllowNoneSignatureType : signature non vérifiée.':
    'ParseUnverified or UnsafeAllowNoneSignatureType: the signature is not verified.',
  'JWT non signé accepté (jjwt)': 'Unsigned JWT accepted (jjwt)',
  'parseClaimsJwt / parseUnsecuredClaims acceptent des jetons sans signature.':
    'parseClaimsJwt / parseUnsecuredClaims accept unsigned tokens.',
  'Algorithme "none" accepté': 'Algorithm "none" accepted',
  'Les jetons non signés sont acceptés.': 'Unsigned tokens are accepted.',
  'La signature du jeton n\'est pas vérifiée : n\'importe qui peut forger un jeton.':
    'The token signature is not checked: anyone can forge a token.',
  'Validation JWT désactivée (.NET)': 'JWT validation disabled (.NET)',
  'Un paramètre de validation essentiel du jeton est désactivé.':
    'An essential token validation parameter is switched off.',
  ['Toujours vérifier la signature avec une liste explicite d\'algorithmes autorisés (jamais "none") et '
    + 'valider exp, iss et aud.']:
    'Always verify the signature against an explicit list of allowed algorithms (never "none") and validate '
    + 'exp, iss and aud.',

  // --- Configuration TLS/SSH
  'Suite TLS faible': 'Weak TLS cipher suite',
  'Suite de chiffrement TLS obsolète référencée dans le code.':
    'Outdated TLS cipher suite referenced in the code.',
  'Suites TLS faibles activées': 'Weak TLS cipher suites enabled',
  'La liste de suites active des suites obsolètes.': 'The cipher suite list enables outdated suites.',
  'Protocole SSL/TLS obsolète activé': 'Outdated SSL/TLS protocol enabled',
  'SSLv2/SSLv3/TLS 1.0/TLS 1.1 activé explicitement (POODLE, BEAST, retiré par la RFC 8996).':
    'SSLv2/SSLv3/TLS 1.0/TLS 1.1 explicitly enabled (POODLE, BEAST, withdrawn by RFC 8996).',
  'Algorithmes SSH faibles': 'Weak SSH algorithms',
  'La configuration SSH active des algorithmes obsolètes.':
    'The SSH configuration enables outdated algorithms.',
  "Clé tirée d'un texte écrit dans le code":
    "Key derived from a text written in the code",
  "La clé de chiffrement est obtenue à partir d'une chaîne écrite dans le code source, transmise jusqu'à SecretKeySpec : quiconque lit le code ou le binaire la connaît.":
    "The encryption key is derived from a string written in the source code and passed down to SecretKeySpec: anyone who reads the code or the binary knows it.",
  "Générer la clé (KeyGenerator) ou la lire depuis un coffre ou un magasin de clés ; jamais depuis une chaîne du code.":
    "Generate the key (KeyGenerator) or read it from a vault or a keystore; never from a string of the code.",
  "Vérification TLS désactivée (Lua)":
    "TLS verification disabled (Lua)",
  "La requête HTTPS accepte n'importe quel certificat (ssl_verify = false) : le trafic peut être intercepté.":
    "The HTTPS request accepts any certificate (ssl_verify = false): the traffic can be intercepted.",
  "Laisser ssl_verify à true et configurer lua_ssl_trusted_certificate avec les autorités de confiance.":
    "Keep ssl_verify to true and set lua_ssl_trusted_certificate with the trusted authorities.",
  "Vérification TLS désactivée (R)":
    "TLS verification disabled (R)",
  "La configuration curl/httr désactive la vérification du certificat ou du nom du serveur.":
    "The curl/httr configuration disables the verification of the certificate or of the server name.",
  "Retirer ssl_verifypeer et ssl_verifyhost ; pour une autorité interne, la déclarer avec cainfo.":
    "Remove ssl_verifypeer and ssl_verifyhost; for an internal authority, declare it with cainfo.",
  "Aléa tiré de la blockchain (Solidity)":
    "Randomness drawn from the blockchain (Solidity)",
  "Un hachage de valeurs du bloc (horodatage, difficulté, blockhash) est prévisible et influençable par les validateurs : il ne doit pas servir de source d'aléa.":
    "A hash of block values (timestamp, difficulty, blockhash) is predictable and can be influenced by validators: it must not be used as a source of randomness.",
  "Utiliser un oracle d'aléa vérifiable (VRF) ou un schéma d'engagement/révélation.":
    "Use a verifiable randomness oracle (VRF) or a commit-reveal scheme.",
  "Trafic en clair autorisé (Android)":
    "Cleartext traffic allowed (Android)",
  "L'application Android accepte des connexions HTTP non chiffrées.":
    "The Android application accepts unencrypted HTTP connections.",
  "Retirer usesCleartextTraffic et cleartextTrafficPermitted=\"true\" ; si un domaine l'exige vraiment, le limiter à ce domaine dans network_security_config.xml.":
    "Remove usesCleartextTraffic and cleartextTrafficPermitted=\"true\"; if a domain really requires it, limit it to that domain in network_security_config.xml.",
  "Autorités ajoutées par l'utilisateur acceptées (Android)":
    "User-added authorities trusted (Android)",
  "La configuration réseau fait confiance aux certificats installés par l'utilisateur : une autorité ajoutée sur l'appareil permet d'intercepter le trafic TLS.":
    "The network configuration trusts user-installed certificates: an authority added on the device makes TLS traffic interception possible.",
  "Ne faire confiance qu'aux autorités système ; réserver les certificats utilisateur au bloc debug-overrides.":
    "Trust system authorities only; keep user certificates for the debug-overrides block.",
  "App Transport Security désactivé (iOS)":
    "App Transport Security disabled (iOS)",
  "Info.plist autorise des connexions HTTP non chiffrées ou contourne les exigences TLS d'App Transport Security.":
    "Info.plist allows unencrypted HTTP connections or bypasses the TLS requirements of App Transport Security.",
  "Retirer NSAllowsArbitraryLoads ; si un domaine l'exige, déclarer une exception limitée à ce domaine dans NSExceptionDomains.":
    "Remove NSAllowsArbitraryLoads; if a domain requires it, declare an exception limited to that domain in NSExceptionDomains.",
  "TLS 1.0 ou 1.1 accepté (iOS)":
    "TLS 1.0 or 1.1 accepted (iOS)",
  "Une exception App Transport Security abaisse la version minimale de TLS à 1.0 ou 1.1.":
    "An App Transport Security exception lowers the minimum TLS version to 1.0 or 1.1.",
  "Exiger TLS 1.2 au minimum (TLSv1.2 ou TLSv1.3).":
    "Require TLS 1.2 at least (TLSv1.2 or TLSv1.3).",
  "Niveau de sécurité OpenSSL abaissé":
    "OpenSSL security level lowered",
  "SECLEVEL 0 ou 1 réactive des clés courtes (RSA de moins de 2048 bits), SHA-1 et des suites obsolètes pour tout le système ou l'application.":
    "SECLEVEL 0 or 1 re-enables short keys (RSA under 2048 bits), SHA-1 and outdated suites for the whole system or application.",
  "Garder SECLEVEL=2 au minimum (valeur par défaut des distributions récentes).":
    "Keep SECLEVEL=2 at least (the default of recent distributions).",
  'jdk.tls.disabledAlgorithms trop permissif': 'jdk.tls.disabledAlgorithms too permissive',
  ['La redéfinition de jdk.tls.disabledAlgorithms réactive des protocoles ou algorithmes interdits par '
    + 'défaut dans le JDK.']:
    'Redefining jdk.tls.disabledAlgorithms re-enables protocols or algorithms that the JDK disallows by '
    + 'default.',
  ['N\'activer que des suites AEAD avec échange de clés éphémère (ECDHE + AES-GCM ou ChaCha20-Poly1305) et '
    + 'TLS 1.3 ; voir les guides TLS de l\'ANSSI et de Mozilla (profil "intermediate").']:
    'Enable only AEAD suites with ephemeral key agreement (ECDHE + AES-GCM or ChaCha20-Poly1305) and TLS '
    + '1.3; see the TLS guides from ANSSI and Mozilla ("intermediate" profile).',
  'N\'autoriser que TLS 1.2 et TLS 1.3.': 'Allow TLS 1.2 and TLS 1.3 only.',
  ['Restreindre Ciphers, MACs, KexAlgorithms et HostKeyAlgorithms aux algorithmes modernes '
    + '(chacha20-poly1305, aes-gcm, curve25519, sntrup761x25519/mlkem768x25519 pour le post-quantique).']:
    'Restrict Ciphers, MACs, KexAlgorithms and HostKeyAlgorithms to modern algorithms (chacha20-poly1305, '
    + 'aes-gcm, curve25519, sntrup761x25519/mlkem768x25519 for post-quantum).',
  'Partir de la valeur par défaut du JDK et n\'y ajouter que des restrictions (ne jamais en retirer).':
    'Start from the JDK default and only add restrictions to it (never remove any).',
};
