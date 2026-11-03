// Catalogue d'algorithmes : notes et recommandations (première moitié, ordre alphabétique de l'original).
// Source : backend/src/main/resources/catalog/default-catalog.json.
// Les noms d'OID (id-sha256, rsaEncryption...) ne sont pas traduits : ce sont des identifiants.

export const CATALOGUE_A = {
  '112 bits de sécurité ; retrait proposé après 2030 (projet SP 800-131A Rev.3).':
    '112-bit security; withdrawal proposed after 2030 (draft SP 800-131A Rev.3).',
  '112 bits de sécurité seulement.': 'Only 112-bit security.',
  '112 bits de sécurité.': '112-bit security.',
  '128-EEA2 (AES) ou 128-EEA3 (ZUC).': '128-EEA2 (AES) or 128-EEA3 (ZUC).',
  '224 bits de sécurité (RFC 7748).': '224-bit security (RFC 7748).',
  'AES en dehors de la Corée.': 'AES outside Korea.',
  'AES ou Camellia.': 'AES or Camellia.',
  'AES ou ChaCha20-Poly1305.': 'AES or ChaCha20-Poly1305.',
  'AES ou ChaCha20.': 'AES or ChaCha20.',
  'AES-256 (ou Kuznyechik si une conformité russe est imposée).':
    'AES-256 (or Kuznyechik if Russian compliance is required).',
  'AES-256 hors contexte réglementaire.': 'AES-256 outside a regulatory context.',
  'AES-256 ou XChaCha20.': 'AES-256 or XChaCha20.',
  "AES-GCM ou ChaCha20-Poly1305 si l'interopérabilité prime.":
    'AES-GCM or ChaCha20-Poly1305 where interoperability matters most.',
  'AES-GCM-SIV pour une résistance normalisée à la réutilisation de nonce.':
    'AES-GCM-SIV for standardised resistance to nonce reuse.',
  'AES.': 'AES.',
  'Acceptable avec AES-CCMP et une phrase de passe robuste (vulnérable au cassage hors ligne sinon).':
    'Acceptable with AES-CCMP and a strong passphrase (otherwise open to offline cracking).',
  'Acceptable avec des groupes DH >= 3072 bits / ECP-256+ ; RFC 9370 pour l\'hybride post-quantique.':
    'Acceptable with DH groups >= 3072 bits / ECP-256+; RFC 9370 for post-quantum hybrids.',
  'Acceptable avec des suites AEAD et ECDHE.': 'Acceptable with AEAD suites and ECDHE.',
  'Acceptable avec des suites AEAD.': 'Acceptable with AEAD suites.',
  "Acceptable avec un grand nombre d'itérations (>= 600 000 pour HMAC-SHA-256 selon l'OWASP).":
    'Acceptable with a high iteration count (>= 600,000 for HMAC-SHA-256 as OWASP recommends).',
  'Algorithme des réseaux mobiles 3G/4G ; clé de 128 bits.':
    '3G/4G mobile network algorithm; 128-bit key.',
  'Algorithme des réseaux mobiles 4G/5G (3GPP), sûr à ce jour.':
    '4G/5G mobile network algorithm (3GPP), safe as things stand.',
  'Algorithme obsolète et faible.': 'Outdated and weak algorithm.',
  "Aléa matériel Intel/AMD ; à combiner avec le générateur du système plutôt qu'à utiliser seul.":
    'Intel/AMD hardware randomness; mix it with the system generator rather than using it alone.',
  'Argon2id ou bcrypt.': 'Argon2id or bcrypt.',
  'Argon2id pour les nouvelles applications.': 'Argon2id for new applications.',
  'Argon2id, yescrypt ou bcrypt.': 'Argon2id, yescrypt or bcrypt.',
  "Ascon (standard NIST pour l'embarqué) ou AES.": 'Ascon (the NIST standard for embedded) or AES.',
  'Ascon ou AES.': 'Ascon or AES.',
  "Ascon pour l'embarqué.": 'Ascon for embedded work.',
  'Attaque POODLE (RFC 7568).': 'POODLE attack (RFC 7568).',
  'Attaques pratiques par clés liées ; remplacé par SNOW 3G, AES et ZUC dans les réseaux mobiles.':
    'Practical related-key attacks; replaced by SNOW 3G, AES and ZUC in mobile networks.',
  'Authentification SAE résistante au cassage hors ligne.':
    'SAE authentication, resistant to offline cracking.',
  'Authentification par mot de passe sans le transmettre ; fondé sur le logarithme discret.':
    'Password authentication without sending the password; based on the discrete logarithm.',
  'Biais statistiques exploitables ; interdit dans TLS (RFC 7465).':
    'Exploitable statistical biases; banned in TLS (RFC 7465).',
  ['Bloc de 128 bits, clé de 256 bits. Aucune attaque pratique, mais conception de la boîte S contestée et '
    + 'absence d\'évaluation ANSSI/NIST : réservé aux obligations réglementaires russes.']:
    '128-bit block, 256-bit key. No practical attack, but the S-box design is disputed and there is no '
    + 'ANSSI/NIST evaluation: keep it for Russian regulatory obligations.',
  'Bloc de 64 bits (Sweet32) ; XXTEA est vulnérable à des attaques à textes choisis.':
    '64-bit block (Sweet32); XXTEA is open to chosen-plaintext attacks.',
  'Bloc de 64 bits : exposé aux attaques par anniversaire (Sweet32) au-delà de quelques Go par clé.':
    '64-bit block: open to birthday attacks (Sweet32) beyond a few GB per key.',
  'Bloc de 64 bits, cryptanalyse intégrale complète (2015).':
    '64-bit block, full integral cryptanalysis (2015).',
  'Blocs de 64 bits (Sweet32).': '64-bit blocks (Sweet32).',
  'Blocs de 64 bits (attaque Sweet32) ; chiffrement interdit par le NIST depuis fin 2023.':
    '64-bit blocks (Sweet32 attack); encryption disallowed by NIST since the end of 2023.',
  'Blocs de 64 bits.': '64-bit blocks.',
  'CMAC ou HMAC-SHA-256.': 'CMAC or HMAC-SHA-256.',
  'CMAC ou HMAC.': 'CMAC or HMAC.',
  'CTR_DRBG ou HMAC_DRBG, ou le générateur du système.':
    'CTR_DRBG or HMAC_DRBG, or the system generator.',
  'Candidat NIST non retenu (HQC choisi en 2025) ; non normalisé.':
    'NIST candidate not selected (HQC was chosen in 2025); not standardised.',
  'Candidat post-quantique cassé en 2022 (attaque classique en quelques heures).':
    'Post-quantum candidate broken in 2022 (classical attack in a few hours).',
  'Candidat post-quantique cassé en 2022 (clé retrouvée en un week-end sur un portable).':
    'Post-quantum candidate broken in 2022 (key recovered over a weekend on a laptop).',
  ["Cassable par l'algorithme de Shor. Pour une sécurité classique de 256 bits, le NIST indique RSA-15360 : "
    + 'augmenter la taille ne protège pas du quantique, seule la migration post-quantique le fait.']:
    'Breakable by Shor\'s algorithm. For 256-bit classical security NIST points to RSA-15360: raising the '
    + 'key size does not protect against quantum computers, only post-quantum migration does.',
  'ChaCha20-Poly1305 pour l\'interopérabilité.': 'ChaCha20-Poly1305 for interoperability.',
  'ChaCha20-Poly1305.': 'ChaCha20-Poly1305.',
  'Chaînes de communauté transmises en clair.': 'Community strings sent in clear text.',
  'Chiffrement GSM cassé en temps réel (tables précalculées).':
    'GSM encryption broken in real time (precomputed tables).',
  "Chiffrement authentifié très rapide sur processeurs AES-NI ; en cours de normalisation à l'IETF.":
    'Very fast authenticated encryption on AES-NI processors; being standardised at the IETF.',
  'Chiffrement coréen (bloc de 128 bits), normalisé ISO/IEC 29192-2.':
    'Korean cipher (128-bit block), standardised in ISO/IEC 29192-2.',
  'Chiffrement homomorphe additif fondé sur la factorisation : cassable par Shor.':
    'Additively homomorphic encryption based on factoring: breakable by Shor.',
  ['Chiffrement hybride à clé publique (MLS, ECH, OHTTP) ; sa sécurité quantique dépend du KEM choisi '
    + '(DHKEM X25519 par défaut, cassable par Shor).']:
    'Hybrid public-key encryption (MLS, ECH, OHTTP); its quantum security depends on the KEM chosen (DHKEM '
    + 'X25519 by default, breakable by Shor).',
  'Chiffrement léger de la NSA rejeté par l\'ISO (2018) faute de justification de conception.':
    'NSA lightweight cipher rejected by ISO (2018) for want of design rationale.',
  'Chiffrement léger de la NSA rejeté par l\'ISO (2018).':
    'NSA lightweight cipher rejected by ISO (2018).',
  'Chiffrement à blocs réglables de Skein ; non normalisé.':
    'Tweakable block cipher from Skein; not standardised.',
  'Chiffrements légers du portefeuille eSTREAM (matériel contraint).':
    'Lightweight ciphers from the eSTREAM portfolio (constrained hardware).',
  'Clé de 56 bits cassable par force brute.': '56-bit key, breakable by brute force.',
  'Clé de 80 bits, retiré par le NIST en 2010.': '80-bit key, withdrawn by NIST in 2010.',
  'Clé retrouvée en quelques minutes.': 'Key recovered in minutes.',
  "Clé sur courbe elliptique : cassable par l'algorithme de Shor.":
    'Elliptic-curve key: breakable by Shor\'s algorithm.',
  'Clés équivalentes et attaques par clés liées ; bloc de 64 bits.':
    'Equivalent keys and related-key attacks; 64-bit block.',
  'Collisions calculables en quelques secondes.': 'Collisions computable in seconds.',
  'Collisions pratiques (SHAttered) ; interdit pour les signatures, retrait complet prévu fin 2030.':
    'Practical collisions (SHAttered); disallowed for signatures, full withdrawal planned for the end of '
    + '2030.',
  'Collisions pratiques.': 'Practical collisions.',
  'Contexte "SSL" générique : peut autoriser des versions obsolètes selon la plateforme.':
    'Generic "SSL" context: it may allow outdated versions depending on the platform.',
  "Conçu pour les tables de hachage, pas pour l'authentification forte.":
    'Designed for hash tables, not for strong authentication.',
  'Conçus pour les tables de hachage : collisions faciles à fabriquer, inadaptés à la sécurité.':
    'Designed for hash tables: collisions are easy to craft, unfit for security.',
  'DTLS 1.3 (ou 1.2).': 'DTLS 1.3 (or 1.2).',
  'DTLS 1.3.': 'DTLS 1.3.',
  'Demander explicitement TLSv1.3 ou TLSv1.2.': 'Ask explicitly for TLSv1.3 or TLSv1.2.',
  "Déclaré obsolète par son auteur (2012) : cassé rapidement sur GPU.":
    'Declared obsolete by its author (2012): cracked quickly on GPUs.',
  'Déprécié par la RFC 8996.': 'Deprecated by RFC 8996.',
  "Dérivation du secret partagé d'un échange de clés.":
    'Derivation from the shared secret of a key agreement.',
  "Dérivation à partir d'une clé secrète (mode compteur / feedback / double pipeline).":
    'Derivation from a secret key (counter / feedback / double-pipeline mode).',
  'Désactiver LM, Kerberos AES et authentification moderne (FIDO2, certificats).':
    'Disable LM, use Kerberos AES and modern authentication (FIDO2, certificates).',
  'Empreintes de mots de passe Windows sans sel (MD4) : réutilisables telles quelles (pass-the-hash).':
    'Windows password hashes without salt (MD4): reusable as they are (pass-the-hash).',
  'Exposé aux attaques par relais ; retiré par Microsoft.':
    'Open to relay attacks; withdrawn by Microsoft.',
  'Falsifiable pour des messages de longueur variable.': 'Forgeable for variable-length messages.',
  'Finaliste AES sans attaque pratique connue, mais peu utilisé et peu évalué depuis.':
    'AES finalist with no known practical attack, but little used and little studied since.',
  'Finaliste AES, non standardisé.': 'AES finalist, not standardised.',
  'Finaliste AES, sans attaque pratique mais quasiment plus utilisé.':
    'AES finalist, no practical attack but hardly used any more.',
  'Finaliste NIST abandonné au profit de ML-KEM ; non normalisé.':
    'NIST finalist dropped in favour of ML-KEM; not standardised.',
  'Fonction de dérivation de TLS 1.2 (HMAC-SHA-256/384).':
    'TLS 1.2 key derivation function (HMAC-SHA-256/384).',
  'Fonction de hachage cassée.': 'Broken hash function.',
  'Générateur Java historique, graine parfois prévisible.':
    'Historic Java generator, sometimes with a predictable seed.',
  'Générateur du système (SecureRandom, secrets, crypto.getRandomValues).':
    'System generator (SecureRandom, secrets, crypto.getRandomValues).',
  'Générateur du système.': 'System generator.',
  'Générateur à porte dérobée présumée (NSA), retiré par le NIST en 2014.':
    'Generator with a suspected backdoor (NSA), withdrawn by NIST in 2014.',
  'Générateurs SP 800-90A.': 'SP 800-90A generators.',
  "Générateurs à accumulateur d'entropie (FreeBSD, macOS historiques).":
    'Entropy-accumulator generators (FreeBSD, historic macOS).',
  'Génération de signatures DSA retirée de FIPS 186-5.':
    'DSA signature generation removed from FIPS 186-5.',
  'HKDF pour les nouveaux protocoles.': 'HKDF for new protocols.',
  'HMAC-SHA-256 ou Poly1305.': 'HMAC-SHA-256 or Poly1305.',
  "HMAC-SHA-256 pour l'intégrité, SHA-256 pour l'empreinte.":
    'HMAC-SHA-256 for integrity, SHA-256 for hashing.',
  'HPKE avec un KEM hybride (X-Wing, ML-KEM + X25519).':
    'HPKE with a hybrid KEM (X-Wing, ML-KEM + X25519).',
  'Hachage de mots de passe Unix ; acceptable avec beaucoup de tours, mais pas résistant aux GPU.':
    'Unix password hashing; acceptable with many rounds, but not GPU-resistant.',
  'Hachage de mots de passe par défaut de nombreuses distributions Linux ; résistant au matériel dédié.':
    'Default password hashing on many Linux distributions; resistant to dedicated hardware.',
  'Hachage russe actuel ; conception de la boîte S contestée, usage réglementaire.':
    'Current Russian hash; disputed S-box design, regulatory use.',
  'Hybride NTRU Prime + X25519 utilisé par OpenSSH depuis la version 9.0 ; non standardisé par le NIST.':
    'NTRU Prime + X25519 hybrid used by OpenSSH since version 9.0; not standardised by NIST.',
  'IKEv2.': 'IKEv2.',
  'IKEv2/IPsec, WireGuard ou TLS (EAP-TLS).': 'IKEv2/IPsec, WireGuard or TLS (EAP-TLS).',
  'IV aléatoire imprévisible et MAC (encrypt-then-MAC) requis ; sensible aux oracles de bourrage.':
    'An unpredictable random IV and a MAC (encrypt-then-MAC) are required; sensitive to padding oracles.',
  'Imposer DTLS 1.2 minimum.': 'Require DTLS 1.2 as a minimum.',
  'Imposer authPriv avec SHA-2 et AES.': 'Require authPriv with SHA-2 and AES.',
  'Interdire rc4-hmac et des-cbc-*.': 'Disallow rc4-hmac and des-cbc-*.',
  "Intègre TLS 1.3 ; sûr, vérifier la prise en charge de l'échange hybride post-quantique.":
    'Includes TLS 1.3; safe, check support for post-quantum hybrid key agreement.',
  'Jeton JWT non signé : falsifiable par n\'importe qui.': 'Unsigned JWT: anyone can forge it.',
  "KEM post-quantique conservateur recommandé par l'ANSSI/BSI.":
    'Conservative post-quantum KEM recommended by ANSSI and the BSI.',
  ['KEM post-quantique standardisé (niveaux 512, 768 et 1024). L\'ANSSI et le BSI recommandent un usage '
    + 'hybride avec ECDH pendant la transition ; préférer ML-KEM-768 ou ML-KEM-1024 (CNSA 2.0).']:
    'Standardised post-quantum KEM (levels 512, 768 and 1024). ANSSI and the BSI recommend hybrid use with '
    + 'ECDH during the transition; prefer ML-KEM-768 or ML-KEM-1024 (CNSA 2.0).',
  'KEM fondé sur ECIES des normes ETSI (TS 102 941, TS 103 097 : systèmes de transport intelligents).':
    'ECIES-based KEM from the ETSI standards (TS 102 941, TS 103 097: intelligent transport systems).',
  'KEM post-quantique sélectionné par le NIST en 2025 (standard en préparation).':
    'Post-quantum KEM selected by NIST in 2025 (standard being drafted).',
  ['KEM post-quantique très conservateur (codes correcteurs), recommandé par le BSI ; clés publiques de '
    + 'plusieurs centaines de Ko.']:
    'Very conservative post-quantum KEM (error-correcting codes), recommended by the BSI; public keys of '
    + 'several hundred kB.',
  'KEM sur réseaux euclidiens normalisé IEEE 1363.1 mais non retenu par le NIST.':
    'Lattice KEM standardised in IEEE 1363.1 but not selected by NIST.',
  'Kerberos.': 'Kerberos.',
  "L'état complet se déduit de 624 sorties : prévisible, interdit pour des secrets.":
    'The full state follows from 624 outputs: predictable, not for secrets.',
  'La robustesse dépend de la fonction de hachage sous-jacente.':
    'Strength depends on the underlying hash function.',
  'Lauréat CAESAR (usage défensif), résistant à la réutilisation de nonce.':
    'CAESAR winner (defence in depth), resistant to nonce reuse.',
  'MAC universels rapides (SSH) ; sûrs avec un nonce unique.':
    'Fast universal MACs (SSH); safe with a unique nonce.',
  'ML-DSA ou SLH-DSA à terme.': 'ML-DSA or SLH-DSA in the longer term.',
  'ML-DSA ou SLH-DSA.': 'ML-DSA or SLH-DSA.',
  'ML-DSA à terme.': 'ML-DSA in the longer term.',
  'ML-KEM (idéalement en hybride avec X25519).': 'ML-KEM (ideally hybrid with X25519).',
  'ML-KEM ou HQC.': 'ML-KEM or HQC.',
  'ML-KEM pour la conformité.': 'ML-KEM for compliance.',
  'ML-KEM.': 'ML-KEM.',
  'Migrer vers ML-DSA (FIPS 204) ; hybride ECDSA+ML-DSA pendant la transition.':
    'Migrate to ML-DSA (FIPS 204); ECDSA+ML-DSA hybrid during the transition.',
  'Migrer vers ML-DSA.': 'Migrate to ML-DSA.',
  'Migrer vers ML-KEM (FIPS 203) ; hybride X25519+ML-KEM pendant la transition.':
    'Migrate to ML-KEM (FIPS 203); X25519+ML-KEM hybrid during the transition.',
  'Migrer vers ML-KEM (ou hybride X25519MLKEM768).':
    'Migrate to ML-KEM (or the X25519MLKEM768 hybrid).',
  'Migrer vers ML-KEM (idéalement en hybride).': 'Migrate to ML-KEM (ideally in hybrid mode).',
  'Migrer vers ML-KEM.': 'Migrate to ML-KEM.',
  'Mode agressif exposant le secret partagé, déprécié.':
    'Aggressive mode exposing the shared secret, deprecated.',
  'Mots de passe limités à 72 octets.': 'Passwords limited to 72 bytes.',
  'Mots de passe tronqués à 8 caractères, cassés en quelques secondes.':
    'Passwords truncated to 8 characters, cracked in seconds.',
  'Même sécurité que RIPEMD-160.': 'Same security as RIPEMD-160.',
  'NTLMv1 est cassé ; NTLM en général est retiré par Microsoft (relais, pass-the-hash).':
    'NTLMv1 is broken; NTLM as a whole is being retired by Microsoft (relaying, pass-the-hash).',
  'Non approuvé par le NIST, marge de sécurité réduite.':
    'Not approved by NIST, reduced security margin.',
  'Nonce unique impératif.': 'A unique nonce is mandatory.',
  'OPAQUE ou CPace pour les nouveaux protocoles.': 'OPAQUE or CPace for new protocols.',
  'PQXDH (hybride ML-KEM).': 'PQXDH (ML-KEM hybrid).',
  'Peu analysé, non standardisé par le NIST.': 'Little analysed, not standardised by NIST.',
  'Peu évalué, attaques sur versions réduites.': 'Little evaluated, attacks on reduced versions.',
  'Portefeuille eSTREAM (RFC 4503), peu utilisé.': 'eSTREAM portfolio (RFC 4503), little used.',
  'Portefeuille eSTREAM, sans attaque pratique.': 'eSTREAM portfolio, no practical attack.',
  'Privilégier TLS 1.3.': 'Prefer TLS 1.3.',
  ['Protocole Noise (Curve25519, ChaCha20-Poly1305) ; ajouter une clé pré-partagée contre la menace '
    + 'quantique ("récolter maintenant, déchiffrer plus tard").']:
    'Noise protocol (Curve25519, ChaCha20-Poly1305); add a pre-shared key against the quantum threat '
    + '("harvest now, decrypt later").',
  'Protocole cassé (CRC-32, attaques par insertion).':
    'Broken protocol (CRC-32, packet injection attacks).',
  'Protocole cassé (RFC 6176).': 'Broken protocol (RFC 6176).',
  "Préférer AES pour l'interopérabilité.": 'Prefer AES for interoperability.',
  'Préférer Argon2id pour le stockage de mots de passe.':
    'Prefer Argon2id for storing passwords.',
  'Préférer Argon2id.': 'Prefer Argon2id.',
  'Préférer SHA-256 ou plus.': 'Prefer SHA-256 or above.',
  'Préférer XSalsa20-Poly1305 ou ChaCha20-Poly1305.': 'Prefer XSalsa20-Poly1305 or ChaCha20-Poly1305.',
  'Préférer mlkem768x25519-sha256 (OpenSSH 9.9+).': 'Prefer mlkem768x25519-sha256 (OpenSSH 9.9+).',
  'Prévoir la migration vers ML-KEM / ML-DSA.': 'Plan the migration to ML-KEM / ML-DSA.',
  'RSA >= 3072 bits à court terme, puis migration vers ML-KEM (chiffrement) ou ML-DSA (signature).':
    'RSA >= 3072 bits in the short term, then migration to ML-KEM (encryption) or ML-DSA (signing).',
  'RSA-PSS (ou PKCS#1 v1.5) avec SHA-256 et une clé d\'au moins 3072 bits, puis ML-DSA.':
    'RSA-PSS (or PKCS#1 v1.5) with SHA-256 and a key of at least 3072 bits, then ML-DSA.',
  'Refuser alg=none et imposer une liste blanche d\'algorithmes (ex. ES256, EdDSA).':
    'Refuse alg=none and enforce an allowlist of algorithms (e.g. ES256, EdDSA).',
  'Remplacer par AES-256-GCM.': 'Replace with AES-256-GCM.',
  'Remplacer par AES-GCM ou ChaCha20-Poly1305.': 'Replace with AES-GCM or ChaCha20-Poly1305.',
  'Remplacer par AES.': 'Replace with AES.',
  'Remplacer par ECDSA P-256+/Ed25519 à court terme, ML-DSA à terme.':
    'Replace with ECDSA P-256+/Ed25519 in the short term, ML-DSA later.',
  'Remplacer par ML-KEM ou, à court terme, ECIES.':
    'Replace with ML-KEM or, in the short term, ECIES.',
  'Remplacer par SHA-256 (intégrité) ou Argon2id (mots de passe).':
    'Replace with SHA-256 (integrity) or Argon2id (passwords).',
  'Remplacer par SHA-256 ou SHA-3.': 'Replace with SHA-256 or SHA-3.',
};
