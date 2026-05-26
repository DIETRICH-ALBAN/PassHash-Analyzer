#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PassHash Analyzer — Password Security & Hash Analysis Tool
Auteur : Jamein N. Dietrich A.
Projet personnel de cybersécurité

AVERTISSEMENT : Outil éducatif uniquement. L'utilisation non autorisée
de fonctionnalités de cassage de hachages est illégale.
"""

import hashlib
import argparse
import math
import re
import time
import string
import os
from typing import Dict, List, Tuple, Optional
from collections import Counter
from itertools import product

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


# ============================================================
# COULEURS TERMINAL
# ============================================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_banner():
    """Affiche la bannière."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║           🔐 PassHash Analyzer v1.0                  ║
  ║     Password Security & Hash Analysis Tool           ║
  ║     by Jamein N. Dietrich A.                         ║
  ╚═══════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)


# ============================================================
# DICTIONNAIRES DE MOTS DE PASSE COURANTS
# ============================================================
COMMON_PASSWORDS = [
    # Top 100 mots de passe les plus utilisés au monde
    '123456', 'password', '123456789', 'guest', 'qwerty',
    '12345678', '111111', '12345', 'col123456', '123123',
    '1234567890', '1234567', 'password1', '12345678910', '000000',
    'admin', 'iloveyou', 'sunshine', 'princess', 'football',
    'charlie', 'abc123', 'dragon', 'monkey', 'master',
    'login', 'letmein', 'welcome', 'shadow', 'ashley',
    'michael', 'ninja', 'mustang', 'access', 'batman',
    'trustno1', 'passw0rd', 'hello', 'thunder', 'knight',
    'chicken', 'robert', 'dallas', 'winter', 'test',
    'matrix', 'freedom', 'computer', 'george', 'andrea',
    'pepper', 'summer', 'diamond', 'killer', 'jasmine',
    'jordan', 'camaro', 'harley', 'ranger', 'hammer',
    'silver', 'taylor', 'falcon', 'dakota', 'austin',
    'thomas', 'soccer', 'hockey', 'ranger', 'yamaha',
    'secret', 'zxcvbnm', 'arsenal', 'carolina', 'tennis',
    'chester', 'liverpool', 'chelsea', 'amanda', 'andrea',
    'qazwsx', '1q2w3e4r', 'qwerty123', 'password123', 'abc1234',
    'aaaaaa', 'mahalkita', 'pass1234', 'zaq1zaq1', '789456123',
    'password2', 'asdfgh', '1qaz2wsx', '555555', 'love123',
]

# Mots de passe francophones courants
FRENCH_PASSWORDS = [
    'bonjour', 'merci', 'amour', 'chateau', 'voiture',
    'soleil', 'fleur', 'pays', 'maison', 'ecole',
    'chien', 'chat', 'famille', 'liberte', 'egalite',
    'fraternite', 'republique', 'france', 'paris', 'marseille',
]

# Patterns courants dans les mots de passe
COMMON_PATTERNS = [
    (r'^\d+$', 'Numéros uniquement'),
    (r'^[a-z]+$', 'Lettres minuscules uniquement'),
    (r'^[A-Z]+$', 'Lettres majuscules uniquement'),
    (r'^(.)\1+$', 'Caractère répété'),
    (r'^(\d)\1{3,}$', 'Chiffre répété (4+ fois)'),
    (r'^(012|123|234|345|456|567|678|789|890)+$', 'Séquence numérique'),
    (r'^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$', 'Séquence alphabétique'),
    (r'^(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)+$', 'Séquence clavier (ligne)'),
    (r'(password|motdepasse|mdp)', 'Contient "password" ou équivalent'),
    (r'(admin|root|user|login)', 'Contient un nom d\'utilisateur courant'),
]


# ============================================================
# ANALYSE DE FORCE DES MOTS DE PASSE
# ============================================================
class PasswordAnalyzer:
    """Analyseur complet de la force des mots de passe."""
    
    # Critères de notation
    CRITERIA = {
        'length_8+': {'weight': 15, 'desc': 'Longueur ≥ 8 caractères'},
        'length_12+': {'weight': 10, 'desc': 'Longueur ≥ 12 caractères'},
        'has_lowercase': {'weight': 10, 'desc': 'Contient des minuscules'},
        'has_uppercase': {'weight': 10, 'desc': 'Contient des majuscules'},
        'has_digits': {'weight': 10, 'desc': 'Contient des chiffres'},
        'has_special': {'weight': 15, 'desc': 'Contient des caractères spéciaux'},
        'no_common_pattern': {'weight': 15, 'desc': 'Pas de pattern courant'},
        'not_in_dictionary': {'weight': 15, 'desc': 'Absent des dictionnaires'},
    }
    
    def __init__(self):
        self.all_common = set(COMMON_PASSWORDS + FRENCH_PASSWORDS)
    
    def analyze(self, password: str) -> Dict:
        """
        Analyse complète d'un mot de passe.
        
        Args:
            password: Mot de passe à analyser
        
        Returns:
            Dictionnaire avec score, détails et recommandations
        """
        results = {
            'password': password,
            'length': len(password),
            'score': 0,
            'max_score': sum(c['weight'] for c in self.CRITERIA.values()),
            'details': {},
            'patterns_found': [],
            'entropy': self._calculate_entropy(password),
            'crack_time': self._estimate_crack_time(password),
            'recommendations': [],
            'severity': '',
        }
        
        # Vérification de chaque critère
        checks = {
            'length_8+': len(password) >= 8,
            'length_12+': len(password) >= 12,
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password)),
            'no_common_pattern': not self._has_common_pattern(password),
            'not_in_dictionary': password.lower() not in self.all_common,
        }
        
        for criterion, passed in checks.items():
            weight = self.CRITERIA[criterion]['weight']
            results['details'][criterion] = {
                'passed': passed,
                'weight': weight,
                'description': self.CRITERIA[criterion]['desc']
            }
            if passed:
                results['score'] += weight
        
        # Détection des patterns
        results['patterns_found'] = self._detect_patterns(password)
        
        # Pénalité pour patterns trouvés
        pattern_penalty = len(results['patterns_found']) * 5
        results['score'] = max(0, results['score'] - pattern_penalty)
        
        # Sévérité
        percentage = results['score'] / results['max_score'] * 100
        if percentage >= 80:
            results['severity'] = 'Fort'
        elif percentage >= 60:
            results['severity'] = 'Moyen'
        elif percentage >= 40:
            results['severity'] = 'Faible'
        else:
            results['severity'] = 'Très faible'
        
        # Recommandations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calcule l'entropie de Shannon du mot de passe.
        
        L'entropie mesure la quantité d'information du mot de passe.
        Plus elle est élevée, plus le mot de passe est difficile à deviner.
        """
        if not password:
            return 0.0
        
        # Taille de l'alphabet utilisé
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0.0
        
        # Entropie = longueur * log2(taille_alphabet)
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def _estimate_crack_time(self, password: str) -> str:
        """
        Estime le temps nécessaire pour casser le mot de passe
        par force brute avec 10 milliards de tentatives/seconde
        (performance d'un GPU moderne).
        """
        entropy = self._calculate_entropy(password)
        
        if entropy == 0:
            return 'Instantané'
        
        # Nombre de tentatives = 2^entropie
        attempts = 2 ** entropy
        
        # À 10 milliards de tentatives par seconde
        seconds = attempts / 10_000_000_000
        
        if seconds < 1:
            return 'Instantané'
        elif seconds < 60:
            return f'{seconds:.0f} secondes'
        elif seconds < 3600:
            return f'{seconds/60:.0f} minutes'
        elif seconds < 86400:
            return f'{seconds/3600:.1f} heures'
        elif seconds < 86400 * 365:
            return f'{seconds/86400:.0f} jours'
        elif seconds < 86400 * 365 * 1000:
            return f'{seconds/(86400*365):.0f} années'
        elif seconds < 86400 * 365 * 1e9:
            return f'{seconds/(86400*365*1e6):.0f} millions d\'années'
        elif seconds < 86400 * 365 * 1e12:
            return f'{seconds/(86400*365*1e9):.0f} milliards d\'années'
        else:
            return 'Pratiquement impossible'
    
    def _has_common_pattern(self, password: str) -> bool:
        """Vérifie si le mot de passe contient un pattern courant."""
        for pattern, _ in COMMON_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                return True
        return False
    
    def _detect_patterns(self, password: str) -> List[Dict]:
        """Détecte les patterns spécifiques dans le mot de passe."""
        found = []
        for pattern, description in COMMON_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                found.append({'pattern': pattern, 'description': description})
        return found
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Génère des recommandations basées sur l'analyse."""
        recs = []
        
        if results['length'] < 8:
            recs.append('Augmenter la longueur à au moins 8 caractères (12 recommandé)')
        elif results['length'] < 12:
            recs.append('Augmenter la longueur à 12 caractères ou plus pour une sécurité optimale')
        
        if not results['details']['has_lowercase']['passed']:
            recs.append('Ajouter des lettres minuscules')
        if not results['details']['has_uppercase']['passed']:
            recs.append('Ajouter des lettres majuscules')
        if not results['details']['has_digits']['passed']:
            recs.append('Ajouter des chiffres')
        if not results['details']['has_special']['passed']:
            recs.append('Ajouter des caractères spéciaux (!@#$%...)')
        
        if results['details']['not_in_dictionary']['passed'] is False:
            recs.append('⚠ Ce mot de passe est dans les dictionnaires courants — le changer immédiatement')
        
        if results['patterns_found']:
            for p in results['patterns_found']:
                recs.append(f'⚠ Pattern détecté : {p["description"]}')
        
        if results['entropy'] < 40:
            recs.append('Entropie faible (< 40 bits) — vulnérable aux attaques par force brute')
        elif results['entropy'] < 60:
            recs.append('Entropie moyenne — envisager un mot de passe plus complexe')
        
        if not recs:
            recs.append('✅ Mot de passe robuste. Continuez à utiliser des mots de passe uniques par service.')
        
        return recs


# ============================================================
# GÉNÉRATEUR DE HACHAGES
# ============================================================
class HashGenerator:
    """Générateur de hachages pour les algorithmes courants."""
    
    ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']
    
    @staticmethod
    def generate(password: str, algorithm: str = 'all') -> Dict[str, str]:
        """
        Génère le hachage d'un mot de passe.
        
        Args:
            password: Mot de passe à hacher
            algorithm: Algorithme ('md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'all')
        
        Returns:
            Dictionnaire {algorithme: hachage}
        """
        results = {}
        password_bytes = password.encode('utf-8')
        
        if algorithm == 'all':
            for algo in HashGenerator.ALGORITHMS:
                hash_func = getattr(hashlib, algo)
                results[algo.upper()] = hash_func(password_bytes).hexdigest()
            
            # bcrypt si disponible
            if BCRYPT_AVAILABLE:
                salt = bcrypt.gensalt(rounds=12)
                results['BCRYPT'] = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        elif algorithm == 'bcrypt':
            if BCRYPT_AVAILABLE:
                salt = bcrypt.gensalt(rounds=12)
                results['BCRYPT'] = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
            else:
                results['BCRYPT'] = '[bcrypt non installé — pip install bcrypt]'
        else:
            hash_func = getattr(hashlib, algorithm)
            results[algorithm.upper()] = hash_func(password_bytes).hexdigest()
        
        return results


# ============================================================
# CASSEUR DE HACHAGES (ÉDUCATIF)
# ============================================================
class HashCracker:
    """
    Démonstration éducative d'attaque par dictionnaire.
    Utilisée uniquement pour montrer la faiblesse des hachages non salés.
    """
    
    def __init__(self):
        self.wordlist = COMMON_PASSWORDS + FRENCH_PASSWORDS
        # Ajouter des variantes courantes
        for word in list(self.wordlist):
            self.wordlist.extend([
                word + '1', word + '123', word + '!',
                word.capitalize(), word.upper(),
                word[::-1],  # Inversé
            ])
    
    def dictionary_attack(self, target_hash: str, algorithm: str = 'md5') -> Optional[Dict]:
        """
        Tente une attaque par dictionnaire sur un hachage.
        
        Args:
            target_hash: Hachage cible à casser
            algorithm: Algorithme de hachage
        
        Returns:
            Résultat de l'attaque ou None
        """
        if algorithm not in ('md5', 'sha1', 'sha256', 'sha512'):
            print(f"{Colors.RED}[!] Algorithme non supporté pour le cassage : {algorithm}{Colors.END}")
            print(f"    Algorithmes supportés : md5, sha1, sha256, sha512")
            return None
        
        target_hash = target_hash.lower().strip()
        hash_func = getattr(hashlib, algorithm)
        
        print(f"\n{Colors.YELLOW}[*] Attaque par dictionnaire sur {algorithm.upper()}...{Colors.END}")
        print(f"    Hachage cible : {target_hash}")
        print(f"    Taille du dictionnaire : {len(self.wordlist)} mots\n")
        
        start_time = time.time()
        attempts = 0
        
        for word in self.wordlist:
            attempts += 1
            word_hash = hash_func(word.encode('utf-8')).hexdigest()
            
            if word_hash == target_hash:
                elapsed = time.time() - start_time
                result = {
                    'found': True,
                    'password': word,
                    'hash': target_hash,
                    'algorithm': algorithm,
                    'attempts': attempts,
                    'time': elapsed,
                }
                print(f"  {Colors.GREEN}[✓] MOT DE PASSE TROUVÉ !{Colors.END}")
                print(f"      Mot de passe : {Colors.BOLD}{word}{Colors.END}")
                print(f"      Tentatives   : {attempts}")
                print(f"      Temps        : {elapsed:.4f}s")
                print(f"\n  {Colors.YELLOW}[!] Ceci démontre pourquoi les hachages non salés (comme {algorithm.upper()})")
                print(f"      sont vulnérables aux attaques par dictionnaire.{Colors.END}")
                return result
        
        elapsed = time.time() - start_time
        print(f"  {Colors.RED}[✗] Mot de passe non trouvé dans le dictionnaire.{Colors.END}")
        print(f"      Tentatives : {attempts} | Temps : {elapsed:.4f}s")
        
        return {'found': False, 'attempts': attempts, 'time': elapsed}


# ============================================================
# BENCHMARK DE HACHAGES
# ============================================================
def benchmark_hashes(iterations: int = 10000) -> None:
    """
    Compare les performances des algorithmes de hachage.
    Démontre pourquoi bcrypt est plus résistant que MD5/SHA.
    """
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"  ⏱️  Benchmark de Hachages — {iterations:,} itérations")
    print(f"{'='*60}{Colors.END}\n")
    
    test_password = "TestPassword123!".encode('utf-8')
    
    algorithms = {
        'MD5': lambda: hashlib.md5(test_password).hexdigest(),
        'SHA-1': lambda: hashlib.sha1(test_password).hexdigest(),
        'SHA-256': lambda: hashlib.sha256(test_password).hexdigest(),
        'SHA-512': lambda: hashlib.sha512(test_password).hexdigest(),
    }
    
    if BCRYPT_AVAILABLE:
        algorithms['BCRYPT (12 rounds)'] = lambda: bcrypt.hashpw(test_password, bcrypt.gensalt(rounds=12))
    
    results = {}
    
    for name, func in algorithms.items():
        print(f"  Test de {name}...", end=' ')
        start = time.time()
        for _ in range(iterations):
            func()
        elapsed = time.time() - start
        results[name] = elapsed
        
        # Pour bcrypt, on ne fait que 10 itérations car c'est très lent (intentionnel)
        if name.startswith('BCRYPT'):
            # Extrapoler
            elapsed_10k = elapsed * (iterations / min(iterations, 10))
            results[name] = elapsed_10k
            print(f"(seulement {min(iterations, 10)} itérations)")
        
        print(f"→ {elapsed:.4f}s ({iterations/elapsed:.0f} hachages/s)")
        
        if name.startswith('BCRYPT') and iterations > 10:
            # Re-run avec moins d'itérations pour bcrypt
            start = time.time()
            for _ in range(10):
                func()
            elapsed = time.time() - start
            results[name] = elapsed * (iterations / 10)
    
    # Résumé comparatif
    print(f"\n{Colors.CYAN}{'─'*60}")
    print(f"  📊 Résumé Comparatif")
    print(f"{'─'*60}{Colors.END}")
    
    md5_time = results.get('MD5', 1)
    for name, elapsed in sorted(results.items(), key=lambda x: x[1]):
        speed = iterations / elapsed if elapsed > 0 else float('inf')
        ratio = elapsed / md5_time if md5_time > 0 else 0
        bar = '█' * min(int(ratio * 2), 50)
        
        print(f"  {name:<20} {elapsed:>8.4f}s | {speed:>10,.0f} h/s | {ratio:>6.1f}x | {bar}")
    
    print(f"\n  {Colors.YELLOW}[!] bcrypt est intentionnellement lent pour résister aux attaques.")
    print(f"      C'est pourquoi il est recommandé pour le stockage des mots de passe.{Colors.END}")


# ============================================================
# ANALYSE DE FICHIER DE MOTS DE PASSE
# ============================================================
def analyze_password_file(input_file: str, report_file: str = None) -> None:
    """
    Analyse un fichier contenant des mots de passe (un par ligne).
    """
    if not os.path.exists(input_file):
        print(f"{Colors.RED}[!] Fichier non trouvé : {input_file}{Colors.END}")
        return
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    print(f"\n{Colors.BLUE}[*] Analyse de {len(passwords)} mot(s) de passe...{Colors.END}\n")
    
    analyzer = PasswordAnalyzer()
    results = []
    
    severity_counts = {'Fort': 0, 'Moyen': 0, 'Faible': 0, 'Très faible': 0}
    
    for i, pwd in enumerate(passwords):
        result = analyzer.analyze(pwd)
        results.append(result)
        severity_counts[result['severity']] += 1
        
        severity_color = {
            'Fort': Colors.GREEN,
            'Moyen': Colors.YELLOW,
            'Faible': Colors.RED,
            'Très faible': Colors.RED + Colors.BOLD
        }.get(result['severity'], Colors.END)
        
        print(f"  {i+1}. {severity_color}[{result['severity']}] {Colors.END}{pwd[:20]}{'...' if len(pwd)>20 else ''} "
              f"— Score: {result['score']}/{result['max_score']} | Entropie: {result['entropy']} bits")
    
    # Résumé
    total = len(passwords)
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"  📊 Résumé de l'analyse")
    print(f"{'='*60}")
    print(f"  Total analysé   : {total}")
    print(f"  Forts           : {severity_counts['Fort']} ({severity_counts['Fort']/total*100:.1f}%)")
    print(f"  Moyens          : {severity_counts['Moyen']} ({severity_counts['Moyen']/total*100:.1f}%)")
    print(f"  Faibles         : {severity_counts['Faible']} ({severity_counts['Faible']/total*100:.1f}%)")
    print(f"  Très faibles    : {severity_counts['Très faible']} ({severity_counts['Très faible']/total*100:.1f}%)")
    print(f"{'='*60}{Colors.END}")
    
    # Rapport
    if report_file:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("RAPPORT D'ANALYSE DE MOTS DE PASSE\n")
            f.write("=" * 50 + "\n\n")
            for i, r in enumerate(results):
                f.write(f"Mot de passe #{i+1}: {'*' * len(r['password'])}\n")
                f.write(f"  Force: {r['severity']} ({r['score']}/{r['max_score']})\n")
                f.write(f"  Entropie: {r['entropy']} bits\n")
                f.write(f"  Temps de cassage estimé: {r['crack_time']}\n")
                if r['recommendations']:
                    f.write(f"  Recommandations:\n")
                    for rec in r['recommendations']:
                        f.write(f"    - {rec}\n")
                f.write("\n")
        
        print(f"\n{Colors.GREEN}[✓] Rapport sauvegardé : {report_file}{Colors.END}")


# ============================================================
# FONCTION PRINCIPALE
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='PassHash Analyzer — Password Security & Hash Analysis Tool',
        epilog='Exemple : python passhash.py analyze --password "MonMotDePasse123!"'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # analyze
    analyze_parser = subparsers.add_parser('analyze', help='Analyser la force d\'un mot de passe')
    analyze_parser.add_argument('--password', '-p', type=str, required=True, help='Mot de passe à analyser')
    
    # hash
    hash_parser = subparsers.add_parser('hash', help='Générer des hachages')
    hash_parser.add_argument('--password', '-p', type=str, required=True, help='Mot de passe à hacher')
    hash_parser.add_argument('--algorithm', '-a', type=str, default='all',
                            choices=['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'all'],
                            help='Algorithme de hachage (défaut: all)')
    
    # crack
    crack_parser = subparsers.add_parser('crack', help='Attaque par dictionnaire (éducatif)')
    crack_parser.add_argument('--hash', '-H', type=str, required=True, help='Hachage à casser')
    crack_parser.add_argument('--algorithm', '-a', type=str, default='md5',
                             choices=['md5', 'sha1', 'sha256', 'sha512'],
                             help='Algorithme du hachage (défaut: md5)')
    
    # benchmark
    subparsers.add_parser('benchmark', help='Comparer les performances de hachage')
    
    # analyze-file
    file_parser = subparsers.add_parser('analyze-file', help='Analyser un fichier de mots de passe')
    file_parser.add_argument('--input', '-i', type=str, required=True, help='Fichier de mots de passe')
    file_parser.add_argument('--report', '-r', type=str, default=None, help='Fichier de rapport')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    print_banner()
    
    if args.command == 'analyze':
        analyzer = PasswordAnalyzer()
        result = analyzer.analyze(args.password)
        
        severity_color = {
            'Fort': Colors.GREEN,
            'Moyen': Colors.YELLOW,
            'Faible': Colors.RED,
            'Très faible': Colors.RED + Colors.BOLD
        }.get(result['severity'], Colors.END)
        
        print(f"\n{Colors.BOLD}📋 Résultat de l'analyse{Colors.END}")
        print(f"{'─'*50}")
        print(f"  Mot de passe   : {'*' * len(args.password)}")
        print(f"  Longueur       : {result['length']} caractères")
        print(f"  Force          : {severity_color}{result['severity']}{Colors.END} "
              f"({result['score']}/{result['max_score']})")
        print(f"  Entropie       : {result['entropy']} bits")
        print(f"  Temps de crack : {result['crack_time']}")
        
        print(f"\n{Colors.BOLD}📊 Détails des critères{Colors.END}")
        print(f"{'─'*50}")
        for criterion, info in result['details'].items():
            status = f"{Colors.GREEN}✓{Colors.END}" if info['passed'] else f"{Colors.RED}✗{Colors.END}"
            print(f"  {status} {info['description']} ({info['weight']} pts)")
        
        if result['patterns_found']:
            print(f"\n{Colors.BOLD}⚠️ Patterns détectés{Colors.END}")
            print(f"{'─'*50}")
            for p in result['patterns_found']:
                print(f"  {Colors.RED}→ {p['description']}{Colors.END}")
        
        print(f"\n{Colors.BOLD}💡 Recommandations{Colors.END}")
        print(f"{'─'*50}")
        for rec in result['recommendations']:
            print(f"  → {rec}")
    
    elif args.command == 'hash':
        generator = HashGenerator()
        hashes = generator.generate(args.password, args.algorithm)
        
        print(f"\n{Colors.BOLD}🔐 Hachages générés{Colors.END}")
        print(f"{'─'*60}")
        for algo, hash_value in hashes.items():
            print(f"  {algo:<10} : {hash_value}")
    
    elif args.command == 'crack':
        print(f"{Colors.YELLOW}\n⚠️  MODE ÉDUCATIF — Démonstration d'attaque par dictionnaire{Colors.END}")
        cracker = HashCracker()
        result = cracker.dictionary_attack(args.hash, args.algorithm)
    
    elif args.command == 'benchmark':
        benchmark_hashes()
    
    elif args.command == 'analyze-file':
        analyze_password_file(args.input, args.report)


if __name__ == '__main__':
    main()
