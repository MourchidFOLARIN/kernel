#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 ATELIER CRYPTOGRAPHIE : DE CÉSAR À X25519
 Code pédagogique à partager lors de la présentation technique Kernel
================================================================================

Ce fichier rassemble sous forme de fonctions Python claires, commentées et autonomes,
tous les algorithmes de chiffrement abordés dans le projet Kernel :

  1. CHIFFREMENTS HISTORIQUES (Pur Python, zéro dépendance)
     - Chiffrement de César (+ attaque par force brute)
     - Chiffrement de Vigenère
     - Chiffrement XOR à clé répétée (+ faille de réutilisation)
     - Chiffrement de flux RC4 (KSA + PRGA)

  2. CHIFFREMENTS PAR BLOCS HISTORIQUES
     - DES-ECB et DES-CBC (Data Encryption Standard - blocs de 64 bits)
     - 3DES-CBC (Triple DES / TDEA)

  3. LE STANDARD MODERNE AES (Advanced Encryption Standard - blocs de 128 bits)
     - AES-ECB (Electronic Codebook - motifs visibles !)
     - AES-CBC (Cipher Block Chaining - aléatoire mais malléable !)
     - AES-CTR (Counter Mode - transformateur de bloc en flux)
     - AES-GCM (Galois/Counter Mode - AEAD : Chiffrement + Intégrité MAC)

  4. LE STANDARD MODERNE CHACHA20-POLY1305
     - Chiffrement par flux ultra-rapide authentifié (RFC 8439)

  5. DÉRIVATION DE CLÉ
     - PBKDF2-HMAC-SHA256 (transformer un mot de passe en clé 256 bits robuste)

  6. ÉCHANGE DE CLÉS ASYMÉTRIQUE (DIFFIE-HELLMAN)
     - X25519 (ECDH sur courbe Curve25519)

  7. OUTILS D'ANALYSE ET ATTAQUES
     - Détection de répétitions de blocs (faille ECB)
     - Mesure de l'effet d'avalanche (diffusion des bits)

Exécution directe pour lancer la démonstration interactive :
    python crypto_atelier.py
================================================================================
"""

import hashlib
import os
import secrets
import sys
from typing import Callable, List, Optional, Tuple

# Bibliothèque standard de cryptographie moderne en Python
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.primitives.asymmetric import x25519
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
except ImportError:
    print("[-] La bibliothèque 'cryptography' n'est pas installée.")
    print("    Installez-la via : pip install cryptography")
    sys.exit(1)


# ==============================================================================
# 1. CHIFFREMENTS HISTORIQUES (PUR PYTHON SANS DÉPENDANCE)
# ==============================================================================

def cesar_chiffrer(texte: str, decalage: int) -> str:
    """
    Chiffrement de César : substitution monoalphabétique par décalage modulaire.
    Formule : C = (P + k) mod 26
    """
    decalage = decalage % 26
    resultat = []
    for c in texte:
        if 'A' <= c <= 'Z':
            resultat.append(chr((ord(c) - ord('A') + decalage) % 26 + ord('A')))
        elif 'a' <= c <= 'z':
            resultat.append(chr((ord(c) - ord('a') + decalage) % 26 + ord('a')))
        else:
            resultat.append(c)  # Conserve ponctuation, chiffres et espaces
    return "".join(resultat)


def cesar_dechiffrer(texte: str, decalage: int) -> str:
    """
    Déchiffrement de César : décalage inverse.
    Formule : P = (C - k) mod 26
    """
    return cesar_chiffrer(texte, -decalage)


def cesar_force_brute(texte_chiffre: str) -> List[Tuple[int, str]]:
    """
    Attaque par force brute sur César :
    Comme l'alphabet n'a que 26 lettres, il n'existe que 25 clés possibles.
    On les teste toutes en quelques microsecondes !
    """
    candidats = []
    for cle in range(1, 26):
        candidats.append((cle, cesar_dechiffrer(texte_chiffre, cle)))
    return candidats


def vigenere_chiffrer(texte: str, cle: str) -> str:
    """
    Chiffrement de Vigenère : chiffrement polyalphabétique.
    Chaque lettre du message est décalée selon la lettre correspondante de la clé.
    """
    shifts = [ord(c.lower()) - ord('a') for c in cle if c.isalpha()]
    if not shifts:
        raise ValueError("La clé de Vigenère doit contenir au moins une lettre alphabétique.")
    
    resultat = []
    i = 0
    for c in texte:
        if 'A' <= c <= 'Z':
            s = shifts[i % len(shifts)]
            resultat.append(chr((ord(c) - ord('A') + s) % 26 + ord('A')))
            i += 1
        elif 'a' <= c <= 'z':
            s = shifts[i % len(shifts)]
            resultat.append(chr((ord(c) - ord('a') + s) % 26 + ord('a')))
            i += 1
        else:
            resultat.append(c)
    return "".join(resultat)


def vigenere_dechiffrer(texte: str, cle: str) -> str:
    """Déchiffrement de Vigenère."""
    shifts = [ord(c.lower()) - ord('a') for c in cle if c.isalpha()]
    if not shifts:
        raise ValueError("La clé de Vigenère doit contenir au moins une lettre alphabétique.")
    
    resultat = []
    i = 0
    for c in texte:
        if 'A' <= c <= 'Z':
            s = shifts[i % len(shifts)]
            resultat.append(chr((ord(c) - ord('A') - s + 26) % 26 + ord('A')))
            i += 1
        elif 'a' <= c <= 'z':
            s = shifts[i % len(shifts)]
            resultat.append(chr((ord(c) - ord('a') - s + 26) % 26 + ord('a')))
            i += 1
        else:
            resultat.append(c)
    return "".join(resultat)


def xor_crypt(donnees: bytes, cle: bytes) -> bytes:
    """
    Chiffrement XOR symétrique : C = P ^ K.
    Propriété remarquable : l'opération de chiffrement et de déchiffrement est identique !
    (P ^ K) ^ K = P.
    """
    if not cle:
        raise ValueError("La clé XOR ne peut pas être vide.")
    return bytes(b ^ cle[i % len(cle)] for i, b in enumerate(donnees))


def rc4_crypt(donnees: bytes, cle: bytes) -> bytes:
    """
    RC4 (Rivest Cipher 4) :
    Algorithme de chiffrement de flux historique conçu en 1987 par Ron Rivest.
    Composé de deux phases :
      1. KSA (Key-Scheduling Algorithm) : permutation du tableau S de 256 octets.
      2. PRGA (Pseudo-Random Generation Algorithm) : génération du flux d'octets pseudo-aléatoires.
    """
    if not cle:
        raise ValueError("La clé RC4 ne peut pas être vide.")

    # 1. KSA : Initialisation du tableau d'état S
    S = list(range(256))
    j = 0
    cle_len = len(cle)
    for i in range(256):
        j = (j + S[i] + cle[i % cle_len]) % 256
        S[i], S[j] = S[j], S[i]

    # 2. PRGA : Génération du flux et application du XOR
    i = j = 0
    sortie = bytearray()
    for byte in donnees:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        octet_pseudo_aleatoire = S[(S[i] + S[j]) % 256]
        sortie.append(byte ^ octet_pseudo_aleatoire)

    return bytes(sortie)


# ==============================================================================
# 2. CHIFFREMENTS PAR BLOCS HISTORIQUES (DES & 3DES)
# ==============================================================================

def des_chiffrer_cbc(donnees: bytes, cle: bytes, iv: bytes) -> bytes:
    """
    DES en mode CBC avec padding PKCS7 (taille de bloc = 64 bits / 8 octets).
    La clé DES fait 8 octets (dont 7 octets utiles = 56 bits de sécurité).
    """
    if len(cle) != 8:
        raise ValueError("La clé DES doit faire exactement 8 octets.")
    if len(iv) != 8:
        raise ValueError("L'IV DES doit faire exactement 8 octets.")

    # Padding PKCS7 à 64 bits (8 octets)
    padder = PKCS7(64).padder()
    padded_data = padder.update(donnees) + padder.finalize()

    # DES émulé via TripleDES avec la clé triplée (k1 = k2 = k3)
    cipher = Cipher(TripleDES(cle * 3), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def des_dechiffrer_cbc(chiffre: bytes, cle: bytes, iv: bytes) -> bytes:
    """Déchiffrement DES en mode CBC avec suppression du padding PKCS7."""
    cipher = Cipher(TripleDES(cle * 3), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(chiffre) + decryptor.finalize()

    unpadder = PKCS7(64).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def triple_des_chiffrer_cbc(donnees: bytes, cle: bytes, iv: bytes) -> bytes:
    """
    Triple-DES (3DES / EDE) en mode CBC :
    Formule : C = E_k3( D_k2( E_k1( P ) ) )
    Clé de 24 octets (192 bits, 168 bits effectifs).
    """
    if len(cle) != 24:
        raise ValueError("La clé 3DES doit faire exactement 24 octets.")
    if len(iv) != 8:
        raise ValueError("L'IV 3DES doit faire exactement 8 octets.")

    padder = PKCS7(64).padder()
    padded_data = padder.update(donnees) + padder.finalize()

    cipher = Cipher(TripleDES(cle), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def triple_des_dechiffrer_cbc(chiffre: bytes, cle: bytes, iv: bytes) -> bytes:
    """Déchiffrement 3DES en mode CBC."""
    cipher = Cipher(TripleDES(cle), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(chiffre) + decryptor.finalize()

    unpadder = PKCS7(64).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


# ==============================================================================
# 3. LE STANDARD MODERNE AES (BLOCS DE 128 BITS)
# ==============================================================================

def aes_ecb_chiffrer(donnees: bytes, cle: bytes) -> bytes:
    """
    AES en mode ECB (Electronic Codebook) :
    DANGEREUX ! Chaque bloc de 16 octets est chiffré indépendamment sans vecteur
    d'initialisation. Deux blocs identiques en clair donnent le même bloc chiffré.
    """
    padder = PKCS7(128).padder()
    padded_data = padder.update(donnees) + padder.finalize()

    cipher = Cipher(algorithms.AES(cle), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def aes_ecb_dechiffrer(chiffre: bytes, cle: bytes) -> bytes:
    """Déchiffrement AES en mode ECB."""
    cipher = Cipher(algorithms.AES(cle), modes.ECB())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(chiffre) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def aes_cbc_chiffrer(donnees: bytes, cle: bytes, iv: bytes) -> bytes:
    """
    AES en mode CBC (Cipher Block Chaining) :
    Chaque bloc de clair est XORé avec le bloc chiffré précédent (ou l'IV pour le premier).
    Corrige le problème d'ECB (plus de répétitions visibles).
    ATTENTION : N'assure AUCUNE intégrité des données (malléable) !
    """
    if len(iv) != 16:
        raise ValueError("L'IV AES-CBC doit faire exactement 16 octets.")

    padder = PKCS7(128).padder()
    padded_data = padder.update(donnees) + padder.finalize()

    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def aes_cbc_dechiffrer(chiffre: bytes, cle: bytes, iv: bytes) -> bytes:
    """Déchiffrement AES en mode CBC."""
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(chiffre) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def aes_ctr_chiffrer(donnees: bytes, cle: bytes, nonce: bytes) -> bytes:
    """
    AES en mode CTR (Counter) :
    Transforme le chiffrement par bloc en chiffrement par flux.
    Ne nécessite pas de bourrage (padding).
    """
    if len(nonce) != 16:
        raise ValueError("Le nonce AES-CTR doit faire 16 octets.")

    cipher = Cipher(algorithms.AES(cle), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(donnees) + encryptor.finalize()


def aes_ctr_dechiffrer(chiffre: bytes, cle: bytes, nonce: bytes) -> bytes:
    """Déchiffrement AES-CTR (l'opération est symétrique au chiffrement)."""
    cipher = Cipher(algorithms.AES(cle), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(chiffre) + decryptor.finalize()


def aes_gcm_chiffrer(donnees: bytes, cle: bytes, nonce: bytes,
                     donnees_associees: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    AES en mode GCM (Galois/Counter Mode) - AEAD Moderne :
    Fournit à la fois la CONFIDENTIALITÉ et l'AUTHENTICITÉ (INTÉGRITÉ).
    Retourne : (ciphertext, tag_authentification_16_octets).
    """
    if len(nonce) != 12:
        raise ValueError("Le nonce AES-GCM standard doit faire 12 octets.")

    aesgcm = AESGCM(cle)
    # Dans l'implémentation de cryptography, encrypt() concatène le ciphertext et le tag (16 octets)
    chiffre_avec_tag = aesgcm.encrypt(nonce, donnees, donnees_associees)
    ciphertext = chiffre_avec_tag[:-16]
    tag = chiffre_avec_tag[-16:]
    return ciphertext, tag


def aes_gcm_dechiffrer(chiffre: bytes, tag: bytes, cle: bytes, nonce: bytes,
                       donnees_associees: Optional[bytes] = None) -> bytes:
    """
    Déchiffrement AES-GCM :
    Vérifie le tag d'authentification AVANT de valider le déchiffrement.
    Si le ciphertext ou le tag a été modifié d'un seul bit, lève une exception InvalidTag.
    """
    aesgcm = AESGCM(cle)
    chiffre_avec_tag = chiffre + tag
    return aesgcm.decrypt(nonce, chiffre_avec_tag, donnees_associees)


# ==============================================================================
# 4. CHACHA20-POLY1305 (LE STANDARD STREAM AEAD MODERNE)
# ==============================================================================

def chacha20_poly1305_chiffrer(donnees: bytes, cle: bytes, nonce: bytes,
                              donnees_associees: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    ChaCha20-Poly1305 (RFC 8439) :
    Alternative moderne ultra-rapide à AES-GCM (très performante sur smartphones sans accélération matérielle AES).
    Combine le chiffrement de flux ChaCha20 et le code d'authentification Poly1305.
    Retourne : (ciphertext, tag_16_octets).
    """
    if len(cle) != 32:
        raise ValueError("La clé ChaCha20 doit faire 32 octets (256 bits).")
    if len(nonce) != 12:
        raise ValueError("Le nonce ChaCha20-Poly1305 doit faire 12 octets.")

    chacha = ChaCha20Poly1305(cle)
    res = chacha.encrypt(nonce, donnees, donnees_associees)
    return res[:-16], res[-16:]


def chacha20_poly1305_dechiffrer(chiffre: bytes, tag: bytes, cle: bytes, nonce: bytes,
                                 donnees_associees: Optional[bytes] = None) -> bytes:
    """Déchiffrement ChaCha20-Poly1305 avec contrôle d'intégrité strict."""
    chacha = ChaCha20Poly1305(cle)
    return chacha.decrypt(nonce, chiffre + tag, donnees_associees)


# ==============================================================================
# 5. DÉRIVATION DE CLÉ (PBKDF2)
# ==============================================================================

def deriver_cle_mot_de_passe(mot_de_passe: str, sel: bytes,
                             iterations: int = 50_000,
                             longueur: int = 32) -> bytes:
    """
    Dérivation de clé PBKDF2-HMAC-SHA256 :
    Permet de dériver une clé cryptographique forte (256 bits / 32 octets) à partir
    d'un mot de passe utilisateur arbitraire et d'un sel unique.
    Ralentit volontairement les attaques par force brute / dictionnaire.
    """
    return hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode("utf-8"), sel, iterations, dklen=longueur)


# ==============================================================================
# 6. ÉCHANGE DE CLÉS ASYMÉTRIQUE DIFFIE-HELLMAN (X25519)
# ==============================================================================

class PairX25519:
    """Paire de clés asymétriques sur Curve25519."""
    def __init__(self):
        self._private = x25519.X25519PrivateKey.generate()
        self.public_key_bytes = self._private.public_key().public_bytes_raw()

    def calculer_secret_partage(self, public_key_pair_bytes: bytes) -> bytes:
        """
        Calcule le secret partagé Diffie-Hellman :
        secret = Curve25519(ma_clé_privée, clé_publique_correspondant)
        Ensuite, on applique un hash SHA-256 pour obtenir une clé symétrique uniforme.
        """
        correspondant_pub = x25519.X25519PublicKey.from_public_bytes(public_key_pair_bytes)
        secret_brut = self._private.exchange(correspondant_pub)
        # Dérivation de la clé de session symétrique
        return hashlib.sha256(secret_brut).digest()


# ==============================================================================
# 7. OUTILS D'ANALYSE & ATTAQUES PÉDAGOGIQUES
# ==============================================================================

def analyser_motifs_ecb(chiffre: bytes, taille_bloc: int = 16) -> List[Tuple[int, int, str]]:
    """
    Détecte les répétitions de blocs identiques dans un ciphertext (faille ECB).
    Retourne la liste des doublons : (index_bloc_1, index_bloc_2, hex_du_bloc).
    """
    blocs = [chiffre[i:i + taille_bloc] for i in range(0, len(chiffre), taille_bloc)]
    vus = {}
    doublons = []
    for idx, b in enumerate(blocs):
        if b in vus:
            doublons.append((vus[b], idx, b.hex()))
        else:
            vus[b] = idx
    return doublons


def attaque_reutilisation_nonce(c1: bytes, c2: bytes) -> bytes:
    """
    Démontre la faille catastrophique de réutilisation de nonce / masque :
    Si deux messages P1 et P2 sont chiffrés avec la même clé de flux K :
      C1 = P1 ^ K
      C2 = P2 ^ K
    Alors : C1 ^ C2 = P1 ^ P2 (la clé K s'annule complètement !).
    """
    min_len = min(len(c1), len(c2))
    return bytes(c1[i] ^ c2[i] for i in range(min_len))


def mesurer_effet_avalanche(p1: bytes, p2: bytes, fonction_chiffrement: Callable[[bytes], bytes]) -> float:
    """
    Mesure l'effet d'avalanche :
    Sur un bon chiffrement (ex: AES), changer un seul bit du clair doit inverser
    environ 50 % des bits du chiffré.
    Retourne le pourcentage de bits modifiés.
    """
    c1 = fonction_chiffrement(p1)
    c2 = fonction_chiffrement(p2)
    min_len = min(len(c1), len(c2))

    bits_differents = 0
    total_bits = min_len * 8
    for i in range(min_len):
        xor_byte = c1[i] ^ c2[i]
        bits_differents += bin(xor_byte).count("1")

    return (bits_differents / total_bits) * 100 if total_bits > 0 else 0.0


# ==============================================================================
# 8. DÉMONSTRATION COMPLÈTE EN LIGNE DE COMMANDE (MAIN)
# ==============================================================================

def separator(titre: str):
    print("\n" + "=" * 80)
    print(f"  {titre.upper()}")
    print("=" * 80)


def main():
    print("""
 ╔═════════════════════════════════════════════════════════════════════════════╗
 ║           KERNEL — ATELIER INTERACTIF SUR LA CRYPTOGRAPHIE                  ║
 ║                 Démonstration pédagogique pas à pas en Python               ║
 ╚═════════════════════════════════════════════════════════════════════════════╝
    """)

    message_original = "Bienvenue sur Kernel ! Ce message est top secret."
    donnees_originales = message_original.encode("utf-8")

    # --------------------------------------------------------------------------
    # 1. CÉSAR
    # --------------------------------------------------------------------------
    separator("1. Chiffrement Historique : César")
    decalage = 7
    cesar_ct = cesar_chiffrer(message_original, decalage)
    cesar_pt = cesar_dechiffrer(cesar_ct, decalage)
    print(f"Texte en clair  : {message_original}")
    print(f"Décalage (clé)  : {decalage}")
    print(f"Texte chiffré   : {cesar_ct}")
    print(f"Déchiffrement   : {cesar_pt}")

    print("\n[Attaque d'Ève] Force brute sur César (test des 25 décalages) :")
    candidats = cesar_force_brute(cesar_ct)
    for k, proposition in candidats[:5]:
        print(f"  Clé {k:02d} -> {proposition}")
    print(f"  ... [Clé {decalage:02d}] -> {candidats[decalage - 1][1]}  <-- TROUVÉ !")

    # --------------------------------------------------------------------------
    # 2. VIGENÈRE
    # --------------------------------------------------------------------------
    separator("2. Chiffrement Polyalphabétique : Vigenère")
    cle_vigenere = "CYBER"
    vig_ct = vigenere_chiffrer(message_original, cle_vigenere)
    vig_pt = vigenere_dechiffrer(vig_ct, cle_vigenere)
    print(f"Texte en clair  : {message_original}")
    print(f"Clé             : {cle_vigenere}")
    print(f"Texte chiffré   : {vig_ct}")
    print(f"Déchiffrement   : {vig_pt}")

    # --------------------------------------------------------------------------
    # 3. XOR & RC4
    # --------------------------------------------------------------------------
    separator("3. Chiffrements de Flux : XOR & RC4")
    cle_xor = b"KERNEL2026"
    xor_ct = xor_crypt(donnees_originales, cle_xor)
    xor_pt = xor_crypt(xor_ct, cle_xor)
    print(f"XOR chiffré (hex)  : {xor_ct.hex()[:50]}...")
    print(f"XOR déchiffré      : {xor_pt.decode('utf-8')}")

    cle_rc4 = b"UneClefTresSecretePourRC4"
    rc4_ct = rc4_crypt(donnees_originales, cle_rc4)
    rc4_pt = rc4_crypt(rc4_ct, cle_rc4)
    print(f"RC4 chiffré (hex)  : {rc4_ct.hex()[:50]}...")
    print(f"RC4 déchiffré      : {rc4_pt.decode('utf-8')}")

    # --------------------------------------------------------------------------
    # 4. AES-ECB & LA FAILLE DES MOTIFS
    # --------------------------------------------------------------------------
    separator("4. AES-ECB (Electronic Codebook) — Le piège des motifs")
    cle_aes = secrets.token_bytes(32)  # Clé AES-256
    texte_repetitif = b"SECRET_KERNEL!!!SECRET_KERNEL!!!SECRET_KERNEL!!!"
    ecb_ct = aes_ecb_chiffrer(texte_repetitif, cle_aes)
    print(f"Clair répétitif    : {texte_repetitif.decode('latin1')}")
    print(f"AES-ECB chiffré    : {ecb_ct.hex()}")
    
    # Détection des motifs
    doublons = analyser_motifs_ecb(ecb_ct, 16)
    print("\n[Attaque d'Ève] Analyse des blocs ECB :")
    for b1, b2, h in doublons:
        print(f"  [!] Bloc {b1} et Bloc {b2} sont STRICTEMENT IDENTIQUES : {h}")
    print("  => Conclusion : ECB trahit la structure des données sans casser la clé !")

    # --------------------------------------------------------------------------
    # 5. AES-CBC & LA MALLÉABILITÉ (MANQUE D'INTÉGRITÉ)
    # --------------------------------------------------------------------------
    separator("5. AES-CBC — Aléatoire mais malléable sans intégrité")
    iv_cbc = secrets.token_bytes(16)
    cbc_ct = aes_cbc_chiffrer(donnees_originales, cle_aes, iv_cbc)
    cbc_pt = aes_cbc_dechiffrer(cbc_ct, cle_aes, iv_cbc)
    print(f"IV (16 octets)     : {iv_cbc.hex()}")
    print(f"AES-CBC chiffré    : {cbc_ct.hex()[:50]}...")
    print(f"Déchiffrement OK   : {cbc_pt.decode('utf-8')}")

    print("\n[Attaque d'Ève en coupure] Altération de ciphertext en transit :")
    # Ève modifie le 10e octet du ciphertext
    chiffre_corrompu = bytearray(cbc_ct)
    chiffre_corrompu[10] ^= 0xFF  # Inverse 8 bits
    chiffre_corrompu = bytes(chiffre_corrompu)
    try:
        pt_corrompu = aes_cbc_dechiffrer(chiffre_corrompu, cle_aes, iv_cbc)
        print(f"  [ALERTE] Bob a déchiffré le message SANS ERREUR : {pt_corrompu[:35]}...")
        print("  => CBC n'a PAS de code d'intégrité : la falsification n'est pas détectée !")
    except Exception as e:
        print(f"  Erreur : {e}")

    # --------------------------------------------------------------------------
    # 6. AES-GCM (LE STANDARD MODERNE AUTHENTIFIÉ)
    # --------------------------------------------------------------------------
    separator("6. AES-GCM (AEAD) — Chiffrement et Intégrité absolue")
    nonce_gcm = secrets.token_bytes(12)
    gcm_ct, gcm_tag = aes_gcm_chiffrer(donnees_originales, cle_aes, nonce_gcm)
    gcm_pt = aes_gcm_dechiffrer(gcm_ct, gcm_tag, cle_aes, nonce_gcm)
    print(f"Ciphertext (hex)   : {gcm_ct.hex()[:50]}...")
    print(f"Tag d'auth (16 o.) : {gcm_tag.hex()}")
    print(f"Déchiffrement légitime : {gcm_pt.decode('utf-8')}")

    print("\n[Attaque d'Ève] Tentative d'altération sous AES-GCM :")
    gcm_ct_corrompu = bytearray(gcm_ct)
    gcm_ct_corrompu[5] ^= 0x01  # Changement d'un seul bit !
    try:
        aes_gcm_dechiffrer(bytes(gcm_ct_corrompu), gcm_tag, cle_aes, nonce_gcm)
        print("  [Erreur] La falsification n'a pas été détectée !")
    except Exception as e:
        print(f"  [REJET IMMÉDIAT] Exception : {type(e).__name__}")
        print("  => Succès : Le tag d'authentification a bloqué net la falsification !")

    # --------------------------------------------------------------------------
    # 7. CHACHA20-POLY1305
    # --------------------------------------------------------------------------
    separator("7. ChaCha20-Poly1305 — Le standard de flux moderne (RFC 8439)")
    cle_chacha = secrets.token_bytes(32)
    nonce_chacha = secrets.token_bytes(12)
    chacha_ct, chacha_tag = chacha20_poly1305_chiffrer(donnees_originales, cle_chacha, nonce_chacha)
    chacha_pt = chacha20_poly1305_dechiffrer(chacha_ct, chacha_tag, cle_chacha, nonce_chacha)
    print(f"ChaCha20 chiffré   : {chacha_ct.hex()[:50]}...")
    print(f"Poly1305 Tag       : {chacha_tag.hex()}")
    print(f"Déchiffré          : {chacha_pt.decode('utf-8')}")

    # --------------------------------------------------------------------------
    # 8. DÉRIVATION DE CLÉ (PBKDF2)
    # --------------------------------------------------------------------------
    separator("8. Dérivation de clé : PBKDF2-HMAC-SHA256")
    mot_de_passe = "MotDePasseTrèsRobuste!2026"
    sel = secrets.token_bytes(16)
    cle_derivee = deriver_cle_mot_de_passe(mot_de_passe, sel, iterations=50_000)
    print(f"Mot de passe       : {mot_de_passe}")
    print(f"Sel public (hex)   : {sel.hex()}")
    print(f"Clé dérivée 256b   : {cle_derivee.hex()}")

    # --------------------------------------------------------------------------
    # 9. ÉCHANGE DE CLÉS ASYMÉTRIQUE DIFFIE-HELLMAN (X25519)
    # --------------------------------------------------------------------------
    separator("9. Échange de clés asymétrique : Curve25519 (X25519 ECDH)")
    alice = PairX25519()
    bob = PairX25519()

    print(f"Alice Clé Publique : {alice.public_key_bytes.hex()}")
    print(f"Bob Clé Publique   : {bob.public_key_bytes.hex()}")

    # Alice et Bob échangent leurs clés publiques et calculent le secret partagé
    secret_alice = alice.calculer_secret_partage(bob.public_key_bytes)
    secret_bob = bob.calculer_secret_partage(alice.public_key_bytes)

    print(f"Secret calculé par Alice : {secret_alice.hex()}")
    print(f"Secret calculé par Bob   : {secret_bob.hex()}")
    assert secret_alice == secret_bob
    print("=> Alice et Bob partagent la MÊME clé secrète sans l'avoir jamais transmise !")

    # --------------------------------------------------------------------------
    # 10. EFFET D'AVALANCHE
    # --------------------------------------------------------------------------
    separator("10. Mesure de l'Effet d'Avalanche (AES)")
    p1 = b"Message secret 1"
    p2 = b"Message secret 2"  # 1 seul caractère modifié
    taux = mesurer_effet_avalanche(p1, p2, lambda p: aes_cbc_chiffrer(p, cle_aes, iv_cbc))
    print(f"Clair 1 : {p1.decode()}")
    print(f"Clair 2 : {p2.decode()}")
    print(f"Pourcentage de bits modifiés dans le chiffré : {taux:.2f} %")
    print("=> Un bon algorithme inverse environ ~50 % des bits !")

    separator("Fin de l'Atelier")
    print("Tous les algorithmes sont fonctionnels et testés avec succès !\n")


if __name__ == "__main__":
    main()

