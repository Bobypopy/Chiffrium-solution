// Catalogue d'algorithmes : notes et recommandations (seconde moitié).
// Source : backend/src/main/resources/catalog/default-catalog.json.

export const CATALOGUE_B = {
  'Remplacer par SHA-256.': 'Replace with SHA-256.',
  'Remplacer par X25519MLKEM768.': 'Replace with X25519MLKEM768.',
  'Remplacé par Streebog (GOST R 34.11-2012) ; attaques par collision théoriques.':
    'Replaced by Streebog (GOST R 34.11-2012); theoretical collision attacks.',
  'Renforcement de DES par blanchiment : bloc de 64 bits et sécurité insuffisante.':
    'DES strengthened by whitening: 64-bit block and not enough security.',
  'Retiré en 1995, collisions pratiques.': 'Withdrawn in 1995, practical collisions.',
  'Retiré par le NIST (2016) ; attaque DUHK avec clé fixe.':
    'Withdrawn by NIST (2016); DUHK attack with a fixed key.',
  'Réductible à une recherche DES de 56 bits.': 'Reducible to a 56-bit DES search.',
  'Réseaux 4G/5G (AES, ZUC).': '4G/5G networks (AES, ZUC).',
  'SHA-256 / SHA-3 hors contexte réglementaire.': 'SHA-256 / SHA-3 outside a regulatory context.',
  'SHA-256 ou BLAKE2.': 'SHA-256 or BLAKE2.',
  'SHA-256 ou SHA-3.': 'SHA-256 or SHA-3.',
  "SHA-256/BLAKE2 pour l'intégrité ; SipHash contre les attaques de tables de hachage.":
    'SHA-256/BLAKE2 for integrity; SipHash against hash-table attacks.',
  'SHA3-256 hors écosystème Ethereum.': 'SHA3-256 outside the Ethereum ecosystem.',
  'SHAKE256 pour la conformité FIPS.': 'SHAKE256 for FIPS compliance.',
  'SNMPv3 avec authPriv (SHA-2, AES).': 'SNMPv3 with authPriv (SHA-2, AES).',
  'SSH-2 uniquement.': 'SSH-2 only.',
  'Sans authentification : à associer à Poly1305.': 'No authentication: pair it with Poly1305.',
  'Sans authentification.': 'No authentication.',
  'Schémas PKCS#5 v1 reposant sur MD5/SHA-1 et DES/RC2.':
    'PKCS#5 v1 schemes built on MD5/SHA-1 and DES/RC2.',
  'Schémas homomorphes sur réseaux (BFV, CKKS) pour le long terme.':
    'Lattice-based homomorphic schemes (BFV, CKKS) for the long term.',
  'Signature Schnorr sur secp256k1 (Bitcoin Taproot) ; cassable par Shor.':
    'Schnorr signature on secp256k1 (Bitcoin Taproot); breakable by Shor.',
  'Signature post-quantique (FIPS 206 en cours).': 'Post-quantum signature (FIPS 206 in progress).',
  ['Signature post-quantique standardisée (ML-DSA-44/65/87). ML-DSA-87 exigé par CNSA 2.0 ; signatures '
    + "hybrides (composites) recommandées par l'ANSSI pendant la transition."]:
    'Standardised post-quantum signature (ML-DSA-44/65/87). ML-DSA-87 is required by CNSA 2.0; ANSSI '
    + 'recommends hybrid (composite) signatures during the transition.',
  'Signature post-quantique à base de hachage.': 'Hash-based post-quantum signature.',
  'Signature sur courbes elliptiques russe ; cassable par l\'algorithme de Shor.':
    'Russian elliptic-curve signature; breakable by Shor\'s algorithm.',
  'Signature à état : gestion stricte de l\'état requise.':
    'Stateful signature: the state must be managed strictly.',
  'Signatures agrégeables sur BLS12-381 (Ethereum, Zcash) ; cassables par Shor.':
    'Aggregatable signatures on BLS12-381 (Ethereum, Zcash); breakable by Shor.',
  'Somme de contrôle contre les erreurs accidentelles : trivialement falsifiable, sans valeur de sécurité.':
    'Checksum against accidental errors: trivially forgeable, of no security value.',
  "Source d'aléa du système d'exploitation, à privilégier pour clés, jetons et IV.":
    'Randomness source of the operating system, the one to use for keys, tokens and IVs.',
  ['Standard FIPS 197. AES-128 reste sûr face au quantique (Grover réduit la sécurité à 64 bits effectifs '
    + 'théoriques, jugé suffisant par le NIST).']:
    'FIPS 197 standard. AES-128 remains safe against quantum computers (Grover brings the security down to '
    + 'a theoretical 64 effective bits, which NIST considers enough).',
  'Standard ISO, peu répandu.': 'ISO standard, not widespread.',
  'Standard ISO/CRYPTREC, équivalent à AES.': 'ISO/CRYPTREC standard, on a par with AES.',
  ['Standard NIST de cryptographie légère (2025) : chiffrement authentifié, hachage et XOF pour '
    + "l'embarqué."]:
    'NIST lightweight cryptography standard (2025): authenticated encryption, hashing and XOF for embedded '
    + 'use.',
  'Standard chinois (GB/T 32907).': 'Chinese standard (GB/T 32907).',
  'Standard coréen (KS X 1213).': 'Korean standard (KS X 1213).',
  'Standard coréen, peu répandu.': 'Korean standard, not widespread.',
  'Streebog ou SHA-256.': 'Streebog or SHA-256.',
  "Suivre la migration post-quantique de l'écosystème.":
    'Follow the post-quantum migration of the ecosystem.',
  "Sécurité de 64 bits contre les collisions (RIPEMD-256 n'est pas plus sûr que RIPEMD-128).":
    '64-bit collision security (RIPEMD-256 is no safer than RIPEMD-128).',
  ["Sûr avec des algorithmes modernes ; vérifier l'échange de clés (sntrup761/mlkem768x25519 pour le "
    + 'post-quantique) et désactiver ssh-rsa (SHA-1), diffie-hellman-group1 et les modes CBC.']:
    'Safe with modern algorithms; check the key agreement (sntrup761/mlkem768x25519 for post-quantum) and '
    + 'disable ssh-rsa (SHA-1), diffie-hellman-group1 and the CBC modes.',
  'Sûr avec les types AES (aes256-cts-hmac-sha384-192) ; désactiver RC4-HMAC et DES.':
    'Safe with the AES types (aes256-cts-hmac-sha384-192); disable RC4-HMAC and DES.',
  'TKIP est cassé et retiré de la norme Wi-Fi.': 'TKIP is broken and removed from the Wi-Fi standard.',
  'TLS 1.3 (HKDF).': 'TLS 1.3 (HKDF).',
  'Usage réglementaire uniquement ; prévoir la migration post-quantique.':
    'Regulatory use only; plan the post-quantum migration.',
  'Utiliser ChaCha20-Poly1305.': 'Use ChaCha20-Poly1305.',
  'Utiliser PBES2 (PBKDF2 + AES) ou Argon2id.': 'Use PBES2 (PBKDF2 + AES) or Argon2id.',
  'Utiliser TLS 1.3 (ou TLS 1.2).': 'Use TLS 1.3 (or TLS 1.2).',
  'Utiliser new SecureRandom() ou SecureRandom.getInstanceStrong().':
    'Use new SecureRandom() or SecureRandom.getInstanceStrong().',
  'Utilisé par ECIES ; acceptable avec SHA-256 ou plus.':
    'Used by ECIES; acceptable with SHA-256 or above.',
  "Utilisé par IPsec ; CMAC en est l'évolution normalisée.":
    'Used by IPsec; CMAC is its standardised successor.',
  "Variantes d'ECDSA (Allemagne, Corée) ; cassables par Shor.":
    'ECDSA variants (Germany, Korea); breakable by Shor.',
  'Variantes rapides de Keccak (RFC 9861) ; sûres mais moins répandues que SHAKE.':
    'Fast Keccak variants (RFC 9861); safe but less widespread than SHAKE.',
  ["Version d'origine de SHA-3 avec un bourrage différent (Ethereum) : sûr, mais non interopérable avec "
    + 'SHA3-256.']:
    'Original SHA-3 version with different padding (Ethereum): safe, but not interoperable with SHA3-256.',
  'Version non précisée.': 'Version not specified.',
  'Version négociée selon la plateforme : vérifier que TLS < 1.2 est désactivé.':
    'Version negotiated by the platform: check that TLS below 1.2 is disabled.',
  'Version pré-standard de Kyber, retirée des navigateurs et incompatible avec ML-KEM final.':
    'Pre-standard version of Kyber, removed from browsers and incompatible with final ML-KEM.',
  'Vérifier les algorithmes (RSA-OAEP ou ECDH, AES-GCM, SHA-256).':
    'Check the algorithms (RSA-OAEP or ECDH, AES-GCM, SHA-256).',
  'Vérifier les algorithmes des clés (pas de DSA-1024, SHA-1, CAST5) ; la RFC 9580 modernise le format.':
    'Check the key algorithms (no DSA-1024, SHA-1, CAST5); RFC 9580 modernises the format.',
  'Vérifier les transformations (AES-GCM, SHA-2) et IKEv2.':
    'Check the transforms (AES-GCM, SHA-2) and IKEv2.',
  'WPA3 (ou WPA2-AES).': 'WPA3 (or WPA2-AES).',
  'WPA3.': 'WPA3.',
  'ambigu et non réversible de façon sûre.': 'ambiguous and not safely reversible.',
  'attaques pratiques ; retiré par le NIST (SP 800-38G Rev.1).':
    'practical attacks; withdrawn by NIST (SP 800-38G Rev.1).',
  'bourrage CBC exposé aux oracles de bourrage : préférer un mode AEAD.':
    'CBC padding open to padding oracles: prefer an AEAD mode.',
  "chiffrement préservant le format (SP 800-38G) ; domaine d'au moins un million de valeurs.":
    'format-preserving encryption (SP 800-38G); domain of at least a million values.',
  'courbe Koblitz (Bitcoin), non recommandée hors blockchain.':
    'Koblitz curve (Bitcoin), not recommended outside blockchain use.',
  'courbe chinoise normalisée (GB/T 32918).': 'Chinese standardised curve (GB/T 32918).',
  "courbe moderne sans pièges d'implémentation (RFC 7748).":
    'modern curve without implementation pitfalls (RFC 7748).',
  "courbe publiée par l'ANSSI.": 'curve published by ANSSI.',
  "courbe à couplage d'environ 120 bits de sécurité (Ethereum, Zcash).":
    'pairing-friendly curve of about 120-bit security (Ethereum, Zcash).',
  'courbes binaires retirées de SP 800-186.': 'binary curves removed from SP 800-186.',
  "en chiffrement, vulnérable à l'attaque de Bleichenbacher ; préférer OAEP.":
    'for encryption, open to Bleichenbacher\'s attack; prefer OAEP.',
  'enveloppement de clé (RFC 3394 / 5649).': 'key wrapping (RFC 3394 / 5649).',
  'environ 100 bits de sécurité depuis les attaques exTNFS : préférer BLS12-381.':
    'about 100-bit security since the exTNFS attacks: prefer BLS12-381.',
  'exposé aux oracles de bourrage en mode CBC sans MAC.':
    'open to padding oracles in CBC mode without a MAC.',
  'les blocs identiques donnent des chiffrés identiques (fuite de motifs).':
    'identical blocks give identical ciphertext (patterns leak).',
  'mode AEAD (CTR + OMAC).': 'AEAD mode (CTR + OMAC).',
  'mode non authentifié (utilisé par MTProto) : préférer un mode AEAD.':
    'unauthenticated mode (used by MTProto): prefer an AEAD mode.',
  'mode obsolète.': 'outdated mode.',
  'moins de 112 bits de sécurité.': 'less than 112-bit security.',
  'niveau 1 seulement : l\'ANSSI et le BSI demandent au moins ML-KEM-768.':
    'level 1 only: ANSSI and BSI require at least ML-KEM-768.',
  'CNSA 2.0 exige ML-KEM-1024 pour les systèmes de sécurité nationale.':
    'CNSA 2.0 requires ML-KEM-1024 for national security systems.',
  'niveau 2 seulement : l\'ANSSI et le BSI demandent au moins ML-DSA-65.':
    'level 2 only: ANSSI and BSI require at least ML-DSA-65.',
  'CNSA 2.0 exige ML-DSA-87 pour les systèmes de sécurité nationale.':
    'CNSA 2.0 requires ML-DSA-87 for national security systems.',
  'neutre : attendu pour les modes AEAD (GCM, CCM) et flux (CTR).':
    'neutral: expected for AEAD modes (GCM, CCM) and stream modes (CTR).',
  'nonce unique impératif.': 'a unique nonce is mandatory.',
  "nonce unique requis, pas d'intégrité.": 'a unique nonce is required, no integrity.',
  "pas d'intégrité.": 'no integrity.',
  'recommandée par le BSI.': 'recommended by the BSI.',
  'retiré de la norme ISO.': 'removed from the ISO standard.',
  'réservé au chiffrement de stockage.': 'for storage encryption only.',
  'résistant à la réutilisation de nonce.': 'resistant to nonce reuse.',
  'Échange de clés asynchrone du protocole Signal (X25519) ; cassable par Shor.':
    'Asynchronous key agreement of the Signal protocol (X25519); breakable by Shor.',
  ['Échange de clés hybride : reste sûr tant qu\'un des deux composants résiste (approche recommandée par '
    + "l'ANSSI et le BSI pendant la transition). X25519MLKEM768 est activé par défaut dans les navigateurs, "
    + 'OpenSSL 3.5 et OpenSSH 10.']:
    'Hybrid key agreement: it stays safe as long as one of the two components holds (the approach ANSSI and '
    + 'the BSI recommend during the transition). X25519MLKEM768 is on by default in browsers, OpenSSL 3.5 '
    + 'and OpenSSH 10.',
  'Échanges de clés authentifiés par mot de passe (PAKE) ; cassables par Shor.':
    'Password-authenticated key exchanges (PAKE); breakable by Shor.',
  'Équivalent UDP de TLS 1.1, déprécié par la RFC 8996.':
    'UDP equivalent of TLS 1.1, deprecated by RFC 8996.',
  'Évolution post-quantique hybride de X3DH (Signal, 2023).':
    'Hybrid post-quantum successor to X3DH (Signal, 2023).',
};
