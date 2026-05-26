# 🔐 PassHash Analyzer — Password Security & Hash Analysis Tool

> **Auteur** : Jamein N. Dietrich A.  
> **Contexte** : Projet personnel en cybersécurité — Analyse de la force des mots de passe et démonstration des attaques par hachage

## 📋 Description

PassHash Analyzer est un outil éducatif Python qui permet de :

- **Évaluer la force d'un mot de passe** selon des critères de sécurité avancés (longueur, complexité, dictionnaire, entropie)
- **Générer des hachages** dans les algorithmes courants (MD5, SHA-1, SHA-256, SHA-512, bcrypt)
- **Démontrer les attaques par dictionnaire** sur des hachages MD5/SHA (à des fins éducatives)
- **Comparer la résistance** des différents algorithmes de hachage face aux attaques par force brute
- **Générer des rapports** d'analyse de sécurité des mots de passe

## 🎯 Compétences cybersécurité démontrées

| Compétence | Mise en œuvre |
|-----------|---------------|
| Cryptographie | Hachage MD5, SHA-1, SHA-256, SHA-512, bcrypt |
| Politique de mots de passe | Évaluation de force, entropie, complexité |
| Attaques par dictionnaire | Démonstration éducative sur hachages faibles |
| Sécurité des hachages | Comparaison MD5 vs SHA-256 vs bcrypt |
| Analyse d'entropie | Calcul de l'entropie de Shannon |
| Recherche de compromis | Rainbow tables simplifiées |

## ⚙️ Installation

```bash
git clone https://github.com/<votre-username>/passhash-analyzer.git
cd passhash-analyzer
pip install -r requirements.txt
```

## 🚀 Utilisation

```bash
# Analyser la force d'un mot de passe
python passhash.py analyze --password "MonMotDePasse123!"

# Générer des hachages pour un mot de passe
python passhash.py hash --password "MonMotDePasse123!"

# Attaque par dictionnaire sur un hachage MD5 (éducatif)
python passhash.py crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5

# Comparer les performances de hachage
python passhash.py benchmark

# Analyser un fichier de mots de passe
python passhash.py analyze-file --input passwords.txt --report rapport.txt
```

## ⚠️ Avertissement éthique

Cet outil est conçu **exclusivement à des fins éducatives**. Les attaques par dictionnaire sont implémentées pour démontrer pourquoi les hachages faibles (MD5, SHA-1) sont vulnérables. **Ne l'utilisez jamais contre des systèmes sans autorisation.**

## 📜 Licence

MIT License — Libre d'utilisation à des fins éducatives.
