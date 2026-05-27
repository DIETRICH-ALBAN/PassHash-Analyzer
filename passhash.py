#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PassHash Analyzer - Analyseur de mots de passe et generateur de hachages
Auteur : Jamein N. Dietrich A.

Outil educatif pour :
- Analyser la force d'un mot de passe (longueur, complexite, entropie)
- Calculer l'entropie de Shannon
- Generer des hachages (MD5, SHA-1, SHA-256, SHA-512, bcrypt)
- Simuler une attaque par dictionnaire educative
- Comparer les performances de hachage
- Analyser des fichiers de mots de passe
"""

import argparse
import hashlib
import math
import time
import os
import sys
import string
import random
from collections import Counter


# ============================================================
# SECTION : Analyse de force des mots de passe
# ============================================================

MOTS_DE_PASSE_COMMUNS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "master", "dragon", "login", "princess",
    "football", "shadow", "sunshine", "trustno1", "iloveyou",
    "batman", "access", "hello", "charlie", "donald",
    "password1", "qwerty123", "letmein", "welcome", "admin",
    "motdepasse", "bonjour", "azerty", "123456789", "1234567890"
]


def calculer_entropie_shannon(mot_de_passe):
    """
    Calcule l'entropie de Shannon d'un mot de passe.

    L'entropie de Shannon mesure le degre d'incertitude d'un mot de passe.
    Plus l'entropie est elevee, plus le mot de passe est difficile a deviner.

    Formule : H = - somme(p_i * log2(p_i))
    ou p_i est la probabilite d'apparition de chaque caractere.

    Args:
        mot_de_passe (str): Le mot de passe a analyser

    Returns:
        float: Entropie de Shannon en bits
    """
    if not mot_de_passe:
        return 0.0

    longueur = len(mot_de_passe)
    frequences = Counter(mot_de_passe)
    entropie = 0.0

    for caractere, frequence in frequences.items():
        probabilite = frequence / longueur
        entropie -= probabilite * math.log2(probabilite)

    # Entropie totale = entropie par caractere * longueur
    return round(entropie * longueur, 2)


def calculer_taille_alphabet(mot_de_passe):
    """
    Determine la taille de l'alphabet utilise par le mot de passe.

    Args:
        mot_de_passe (str): Le mot de passe a analyser

    Returns:
        int: Taille de l'alphabet
    """
    taille = 0
    if any(c in string.ascii_lowercase for c in mot_de_passe):
        taille += 26
    if any(c in string.ascii_uppercase for c in mot_de_passe):
        taille += 26
    if any(c in string.digits for c in mot_de_passe):
        taille += 10
    if any(c in string.punctuation for c in mot_de_passe):
        taille += len(string.punctuation)
    return taille


def calculer_entropie_theorique(mot_de_passe):
    """
    Calcule l'entropie theorique d'un mot de passe.
    Formule : E = L * log2(N) ou L = longueur, N = taille de l'alphabet.

    Args:
        mot_de_passe (str): Le mot de passe

    Returns:
        float: Entropie theorique en bits
    """
    taille_alphabet = calculer_taille_alphabet(mot_de_passe)
    if taille_alphabet == 0:
        return 0.0
    return round(len(mot_de_passe) * math.log2(taille_alphabet), 2)


def analyser_complexite(mot_de_passe):
    """
    Analyse la complexite d'un mot de passe en verifiant differents criteres.

    Args:
        mot_de_passe (str): Le mot de passe a analyser

    Returns:
        dict: Details de la complexite
    """
    criteres = {
        "longueur": len(mot_de_passe),
        "minuscules": any(c in string.ascii_lowercase for c in mot_de_passe),
        "majuscules": any(c in string.ascii_uppercase for c in mot_de_passe),
        "chiffres": any(c in string.digits for c in mot_de_passe),
        "speciaux": any(c in string.punctuation for c in mot_de_passe),
        "taille_alphabet": calculer_taille_alphabet(mot_de_passe),
        "caracteres_uniques": len(set(mot_de_passe)),
    }

    # Detection de motifs faibles
    motifs_faibles = []
    if mot_de_passe.lower() in MOTS_DE_PASSE_COMMUNS:
        motifs_faibles.append("Mot de passe tres courant")
    if len(set(mot_de_passe)) == 1:
        motifs_faibles.append("Caracteres repetes identiques")
    if len(mot_de_passe) >= 4:
        for i in range(len(mot_de_passe) - 3):
            sous_chaine = mot_de_passe[i:i+4]
            if sous_chaine.isdigit() and len(set(sous_chaine)) <= 2:
                motifs_faibles.append("Suite numerique simple detectee")
                break
    if mot_de_passe.isalpha():
        motifs_faibles.append("Uniquement des lettres")
    if mot_de_passe.isdigit():
        motifs_faibles.append("Uniquement des chiffres")

    criteres["motifs_faibles"] = motifs_faibles
    return criteres


def evaluer_force_mot_de_passe(mot_de_passe):
    """
    Evalue la force globale d'un mot de passe.

    Args:
        mot_de_passe (str): Le mot de passe a evaluer

    Returns:
        dict: Evaluation complete de la force
    """
    complexite = analyser_complexite(mot_de_passe)
    entropie_shannon = calculer_entropie_shannon(mot_de_passe)
    entropie_theorique = calculer_entropie_theorique(mot_de_passe)

    # Score de force (0-100)
    score = 0

    # Longueur
    longueur = len(mot_de_passe)
    if longueur >= 8:
        score += 15
    if longueur >= 12:
        score += 15
    if longueur >= 16:
        score += 10

    # Diversite des caracteres
    if complexite["minuscules"]:
        score += 10
    if complexite["majuscules"]:
        score += 10
    if complexite["chiffres"]:
        score += 10
    if complexite["speciaux"]:
        score += 15

    # Unicite des caracteres
    ratio_uniques = complexite["caracteres_uniques"] / max(longueur, 1)
    score += int(ratio_uniques * 15)

    # Penalites pour motifs faibles
    for motif in complexite["motifs_faibles"]:
        score -= 15

    score = max(0, min(100, score))

    # Classification
    if score < 25:
        niveau = "TRES FAIBLE"
        couleur = "ROUGE"
    elif score < 50:
        niveau = "FAIBLE"
        couleur = "ORANGE"
    elif score < 75:
        niveau = "MOYEN"
        couleur = "JAUNE"
    else:
        niveau = "FORT"
        couleur = "VERT"

    # Estimation du temps de cassage
    taille_alphabet = complexite["taille_alphabet"]
    if taille_alphabet > 0:
        combinaisons = taille_alphabet ** longueur
        # Hypothese : 10 milliards de tentatives par seconde
        secondes = combinaisons / 1e10
        temps_estime = formater_temps(secondes)
    else:
        temps_estime = "Instantane"

    return {
        "mot_de_passe": mot_de_passe,
        "score": score,
        "niveau": niveau,
        "couleur": couleur,
        "entropie_shannon": entropie_shannon,
        "entropie_theorique": entropie_theorique,
        "complexite": complexite,
        "temps_cassage_estime": temps_estime
    }


def formater_temps(secondes):
    """
    Formate un temps en secondes en chaine lisible.

    Args:
        secondes (float): Temps en secondes

    Returns:
        str: Temps formate
    """
    if secondes < 1:
        return "Instantane"
    elif secondes < 60:
        return f"{secondes:.1f} secondes"
    elif secondes < 3600:
        return f"{secondes/60:.1f} minutes"
    elif secondes < 86400:
        return f"{secondes/3600:.1f} heures"
    elif secondes < 31536000:
        return f"{secondes/86400:.1f} jours"
    elif secondes < 31536000 * 1000:
        return f"{secondes/31536000:.1f} annees"
    elif secondes < 31536000 * 1e6:
        return f"{secondes/31536000/1000:.1f} milliers d'annees"
    elif secondes < 31536000 * 1e9:
        return f"{secondes/31536000/1e6:.1f} millions d'annees"
    else:
        return "Tres long temps (pratiquement incassable)"


def afficher_analyse(resultat):
    """
    Affiche le resultat d'une analyse de mot de passe de maniere formatee.

    Args:
        resultat (dict): Resultat de l'evaluation
    """
    mdp = resultat["mot_de_passe"]
    # Masquage partiel du mot de passe
    if len(mdp) > 4:
        mdp_affiche = mdp[:2] + "*" * (len(mdp) - 4) + mdp[-2:]
    else:
        mdp_affiche = "*" * len(mdp)

    print(f"\n{'='*55}")
    print(f"  Analyse du mot de passe : {mdp_affiche}")
    print(f"{'='*55}")
    print(f"  Score de force       : {resultat['score']}/100")
    print(f"  Niveau               : {resultat['niveau']} ({resultat['couleur']})")
    print(f"  Entropie Shannon     : {resultat['entropie_shannon']} bits")
    print(f"  Entropie theorique   : {resultat['entropie_theorique']} bits")
    print(f"  Temps de cassage     : {resultat['temps_cassage_estime']}")
    print(f"\n  --- Details de la complexite ---")
    c = resultat["complexite"]
    print(f"  Longueur             : {c['longueur']} caracteres")
    print(f"  Minuscules           : {'Oui' if c['minuscules'] else 'Non'}")
    print(f"  Majuscules           : {'Oui' if c['majuscules'] else 'Non'}")
    print(f"  Chiffres             : {'Oui' if c['chiffres'] else 'Non'}")
    print(f"  Caracteres speciaux  : {'Oui' if c['speciaux'] else 'Non'}")
    print(f"  Taille de l'alphabet : {c['taille_alphabet']}")
    print(f"  Caracteres uniques   : {c['caracteres_uniques']}")

    if c["motifs_faibles"]:
        print(f"\n  --- Motifs faibles detectes ---")
        for motif in c["motifs_faibles"]:
            print(f"  [!] {motif}")
    else:
        print(f"\n  Aucun motif faible detecte.")

    print(f"{'='*55}")


# ============================================================
# SECTION : Generation de hachages
# ============================================================

def generer_hachages(mot_de_passe):
    """
    Genere les hachages d'un mot de passe avec differents algorithmes.

    Args:
        mot_de_passe (str): Le mot de passe a hacher

    Returns:
        dict: Dictionnaire algorithme -> hachage
    """
    hachages = {}

    # MD5 (deconseille pour la securite, mais educatif)
    hachages["MD5"] = hashlib.md5(mot_de_passe.encode()).hexdigest()

    # SHA-1 (deconseille pour la securite)
    hachages["SHA-1"] = hashlib.sha1(mot_de_passe.encode()).hexdigest()

    # SHA-256 (recommande)
    hachages["SHA-256"] = hashlib.sha256(mot_de_passe.encode()).hexdigest()

    # SHA-512 (recommande)
    hachages["SHA-512"] = hashlib.sha512(mot_de_passe.encode()).hexdigest()

    # bcrypt (simulation - necessite la bibliotheque bcrypt)
    try:
        import bcrypt
        hachages["bcrypt"] = bcrypt.hashpw(
            mot_de_passe.encode(), bcrypt.gensalt()
        ).decode()
    except ImportError:
        # Simulation educative si bcrypt n'est pas installe
        sel = os.urandom(16).hex()[:22]
        hachage_simule = hashlib.sha256(
            (mot_de_passe + sel).encode()
        ).hexdigest()[:31]
        hachages["bcrypt (simule)"] = f"$2b$12${sel}{hachage_simule}"

    return hachages


def afficher_hachages(mot_de_passe):
    """
    Affiche les hachages generes pour un mot de passe.

    Args:
        mot_de_passe (str): Le mot de passe
    """
    hachages = generer_hachages(mot_de_passe)
    print(f"\n{'='*70}")
    print(f"  Hachages generes")
    print(f"{'='*70}")
    for algo, hachage in hachages.items():
        print(f"  {algo:<18} : {hachage}")
    print(f"{'='*70}")


# ============================================================
# SECTION : Attaque par dictionnaire (educative)
# ============================================================

DICTIONNAIRE_PAR_DEFAUT = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "letmein", "admin", "welcome", "monkey", "master",
    "dragon", "login", "princess", "football", "shadow",
    "sunshine", "trustno1", "iloveyou", "batman", "access",
    "hello", "charlie", "donald", "password1", "qwerty123",
    "motdepasse", "bonjour", "azerty", "1234567890", "root",
    "test", "guest", "info", "webmaster", "user",
    "secret", "pass", "demo", "default", "changeme"
]


def attaque_dictionnaire(hachage_cible, algorithme="SHA-256", fichier_dico=None):
    """
    Simule une attaque par dictionnaire educative.
    Tente de trouver le mot de passe correspondant a un hachage.

    Args:
        hachage_cible (str): Le hachage a casser
        algorithme (str): L'algorithme de hachage utilise
        fichier_dico (str): Chemin vers un fichier de dictionnaire

    Returns:
        tuple: (trouve: bool, mot_de_passe: str, tentatives: int, temps: float)
    """
    # Chargement du dictionnaire
    mots = list(DICTIONNAIRE_PAR_DEFAUT)

    if fichier_dico and os.path.isfile(fichier_dico):
        with open(fichier_dico, "r", encoding="utf-8", errors="ignore") as f:
            for ligne in f:
                mot = ligne.strip()
                if mot:
                    mots.append(mot)
        print(f"[*] Dictionnaire charge : {fichier_dico} ({len(mots)} mots)")
    else:
        print(f"[*] Dictionnaire par defaut utilise ({len(mots)} mots)")

    # Selection de la fonction de hachage
    fonctions_hash = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
    }

    if algorithme not in fonctions_hash:
        print(f"[!] Algorithme non supporte : {algorithme}")
        print(f"    Algorithmes supportes : {', '.join(fonctions_hash.keys())}")
        return False, "", 0, 0.0

    fonction_hash = fonctions_hash[algorithme]

    print(f"[*] Attaque par dictionnaire sur le hachage {algorithme}...")
    print(f"[*] Hachage cible : {hachage_cible}")

    debut = time.time()
    tentatives = 0
    trouve = False
    mot_trouve = ""

    hachage_cible_lower = hachage_cible.lower()

    for mot in mots:
        tentatives += 1
        hachage_calcule = fonction_hash(mot.encode()).hexdigest()

        if hachage_calcule.lower() == hachage_cible_lower:
            trouve = True
            mot_trouve = mot
            break

        if tentatives % 10 == 0:
            print(f"    [{tentatives}] Tentative en cours...")

    temps_ecoule = time.time() - debut

    if trouve:
        print(f"\n    [+] MOT DE PASSE TROUVE : {mot_trouve}")
    else:
        print(f"\n    [-] Mot de passe non trouve dans le dictionnaire")

    print(f"    [*] Tentatives : {tentatives}")
    print(f"    [*] Temps ecoule : {temps_ecoule:.4f} secondes")
    print(f"    [*] Vitesse : {tentatives/max(temps_ecoule, 0.001):.0f} hachages/seconde")

    return trouve, mot_trouve, tentatives, temps_ecoule


# ============================================================
# SECTION : Benchmark de hachage
# ============================================================

def benchmark_hachage(iterations=10000):
    """
    Compare les performances des differents algorithmes de hachage.

    Args:
        iterations (int): Nombre d'iterations pour chaque algorithme

    Returns:
        dict: Resultats du benchmark
    """
    donnees_test = b"Ceci est une donnee de test pour le benchmark de hachage PassHash Analyzer"

    algorithmes = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
    }

    print(f"\n{'='*55}")
    print(f"  Benchmark de hachage ({iterations} iterations)")
    print(f"{'='*55}")

    resultats = {}

    for nom, fonction in algorithmes.items():
        debut = time.time()
        for _ in range(iterations):
            fonction(donnees_test).hexdigest()
        temps = time.time() - debut
        vitesse = iterations / max(temps, 0.001)
        resultats[nom] = {"temps": temps, "vitesse": vitesse}
        print(f"  {nom:<10} : {temps:.4f}s  ({vitesse:.0f} hachages/s)")

    # Test bcrypt si disponible
    try:
        import bcrypt
        iterations_bcrypt = min(iterations, 100)
        debut = time.time()
        for _ in range(iterations_bcrypt):
            bcrypt.hashpw(donnees_test, bcrypt.gensalt())
        temps = time.time() - debut
        vitesse = iterations_bcrypt / max(temps, 0.001)
        resultats["bcrypt"] = {"temps": temps, "vitesse": vitesse}
        print(f"  {'bcrypt':<10} : {temps:.4f}s  ({vitesse:.0f} hachages/s) [{iterations_bcrypt} it.]")
    except ImportError:
        print(f"  {'bcrypt':<10} : Non installe (pip install bcrypt)")

    print(f"{'='*55}")
    print(f"\n  [*] Note : bcrypt est intentionnellement lent pour")
    print(f"      resister aux attaques par force brute.")

    return resultats


# ============================================================
# SECTION : Analyse de fichier de mots de passe
# ============================================================

def analyser_fichier_mots_de_passe(chemin_fichier):
    """
    Analyse un fichier contenant des mots de passe (un par ligne).
    Genere un rapport statistique sur la force des mots de passe.

    Args:
        chemin_fichier (str): Chemin vers le fichier de mots de passe
    """
    if not os.path.isfile(chemin_fichier):
        print(f"[!] Fichier non trouve : {chemin_fichier}")
        return

    with open(chemin_fichier, "r", encoding="utf-8", errors="ignore") as f:
        lignes = f.readlines()

    mots_de_passe = [ligne.strip() for ligne in lignes if ligne.strip()]

    if not mots_de_passe:
        print("[!] Fichier vide ou aucun mot de passe valide.")
        return

    print(f"\n{'='*55}")
    print(f"  Analyse du fichier : {chemin_fichier}")
    print(f"  Nombre de mots de passe : {len(mots_de_passe)}")
    print(f"{'='*55}")

    # Analyse de chaque mot de passe
    resultats = []
    scores = {"TRES FAIBLE": 0, "FAIBLE": 0, "MOYEN": 0, "FORT": 0}

    for mdp in mots_de_passe:
        evaluation = evaluer_force_mot_de_passe(mdp)
        resultats.append(evaluation)
        scores[evaluation["niveau"]] += 1

    # Statistiques globales
    total = len(mots_de_passe)
    longueurs = [len(mdp) for mdp in mots_de_passe]
    entropies = [r["entropie_shannon"] for r in resultats]

    print(f"\n  --- Statistiques globales ---")
    print(f"  Nombre total        : {total}")
    print(f"  Longueur moyenne    : {sum(longueurs)/total:.1f}")
    print(f"  Longueur min/max    : {min(longueurs)}/{max(longueurs)}")
    print(f"  Entropie moyenne    : {sum(entropies)/total:.1f} bits")

    print(f"\n  --- Repartition par force ---")
    print(f"  TRES FAIBLE : {scores['TRES FAIBLE']:>4} ({scores['TRES FAIBLE']/total*100:.1f}%)")
    print(f"  FAIBLE      : {scores['FAIBLE']:>4} ({scores['FAIBLE']/total*100:.1f}%)")
    print(f"  MOYEN       : {scores['MOYEN']:>4} ({scores['MOYEN']/total*100:.1f}%)")
    print(f"  FORT        : {scores['FORT']:>4} ({scores['FORT']/total*100:.1f}%)")

    # Mots de passe les plus faibles
    resultats_tries = sorted(resultats, key=lambda x: x["score"])
    print(f"\n  --- 5 mots de passe les plus faibles ---")
    for i, r in enumerate(resultats_tries[:5], 1):
        mdp = r["mot_de_passe"]
        mdp_affiche = mdp[:2] + "*" * max(len(mdp) - 4, 0) + mdp[-2:] if len(mdp) > 4 else "*" * len(mdp)
        print(f"  {i}. {mdp_affiche:<15} Score: {r['score']}/100 [{r['niveau']}]")

    print(f"{'='*55}")


# ============================================================
# SECTION : Interface CLI
# ============================================================

def main():
    """Point d'entree principal du programme."""
    parser = argparse.ArgumentParser(
        description="PassHash Analyzer - Analyseur de mots de passe et generateur de hachages",
        epilog="Auteur : Jamein N. Dietrich A. | Usage educatif uniquement"
    )

    subparsers = parser.add_subparsers(dest="commande", help="Commandes disponibles")

    # Commande : analyser
    parser_analyser = subparsers.add_parser(
        "analyser", help="Analyser la force d'un mot de passe"
    )
    parser_analyser.add_argument(
        "motdepasse", type=str, help="Mot de passe a analyser"
    )
    parser_analyser.add_argument(
        "--hash", action="store_true", help="Generer aussi les hachages"
    )

    # Commande : hacher
    parser_hacher = subparsers.add_parser(
        "hacher", help="Generer les hachages d'un mot de passe"
    )
    parser_hacher.add_argument(
        "motdepasse", type=str, help="Mot de passe a hacher"
    )

    # Commande : dictionnaire
    parser_dico = subparsers.add_parser(
        "dictionnaire", help="Attaque par dictionnaire educative"
    )
    parser_dico.add_argument(
        "hachage", type=str, help="Hachage a casser"
    )
    parser_dico.add_argument(
        "-a", "--algo", type=str, default="SHA-256",
        choices=["MD5", "SHA-1", "SHA-256", "SHA-512"],
        help="Algorithme de hachage (defaut: SHA-256)"
    )
    parser_dico.add_argument(
        "-f", "--fichier", type=str, default=None,
        help="Fichier dictionnaire personnalise"
    )

    # Commande : benchmark
    subparsers.add_parser(
        "benchmark", help="Comparer les performances de hachage"
    )

    # Commande : fichier
    parser_fichier = subparsers.add_parser(
        "fichier", help="Analyser un fichier de mots de passe"
    )
    parser_fichier.add_argument(
        "chemin", type=str, help="Chemin du fichier de mots de passe"
    )

    args = parser.parse_args()

    if not args.commande:
        parser.print_help()
        return

    if args.commande == "analyser":
        resultat = evaluer_force_mot_de_passe(args.motdepasse)
        afficher_analyse(resultat)
        if args.hash:
            afficher_hachages(args.motdepasse)

    elif args.commande == "hacher":
        afficher_hachages(args.motdepasse)

    elif args.commande == "dictionnaire":
        attaque_dictionnaire(args.hachage, args.algo, args.fichier)

    elif args.commande == "benchmark":
        benchmark_hachage()

    elif args.commande == "fichier":
        analyser_fichier_mots_de_passe(args.chemin)


if __name__ == "__main__":
    main()
