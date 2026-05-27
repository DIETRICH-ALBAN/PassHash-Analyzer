# PassHash Analyzer - Analyseur de mots de passe et generateur de hachages

Auteur : Jamein N. Dietrich A.
Contexte : Projet personnel en cyberscurite - Analyse de force des mots de passe et generation de hachages

## Description

PassHash Analyzer est un outil educatif qui permet d'analyser la force des mots de passe, de generer des hachages cryptographiques avec differents algorithmes, et de comprendre les mecanismes d'attaque par dictionnaire. Il illustre les principes fondamentaux de la securite des mots de passe et du hachage cryptographique.

Fonctionnalites principales :
- Analyse de force des mots de passe (longueur, complexite, motifs faibles)
- Calcul de l'entropie de Shannon et de l'entropie theorique
- Generation de hachages (MD5, SHA-1, SHA-256, SHA-512, bcrypt)
- Simulation educative d'attaque par dictionnaire
- Benchmark comparatif des algorithmes de hachage
- Analyse de fichiers de mots de passe avec statistiques

## Competences cyberscurite demontrees

| Competence | Description |
|---|---|
| Cryptographie | Hachage cryptographique multi-algorithmes |
| Analyse de force | Evaluation de la robustesse des mots de passe |
| Entropie | Calcul de l'entropie de Shannon et theorique |
| Attaque dictionnaire | Comprehension des mecanismes d'attaque |
| Benchmark | Comparaison des performances cryptographiques |
| Forensique | Analyse de fichiers de mots de passe |

## Installation

```bash
git clone <url-du-depot>
cd passhash-analyzer
pip install -r requirements.txt
```

Note : bcrypt est optionnel. Le programme fonctionne en mode simule sans lui.

## Utilisation

Analyser un mot de passe :
```bash
python3 passhash.py analyser "MonMot2Passe!"
```

Analyser avec generation de hachages :
```bash
python3 passhash.py analyser "MonMot2Passe!" --hash
```

Generer les hachages d'un mot de passe :
```bash
python3 passhash.py hacher "MonMot2Passe!"
```

Attaque par dictionnaire educative :
```bash
python3 passhash.py dictionnaire <hachage_sha256> -a SHA-256
```

Attaque avec dictionnaire personnalise :
```bash
python3 passhash.py dictionnaire <hachage> -a MD5 -f mon_dico.txt
```

Benchmark de hachage :
```bash
python3 passhash.py benchmark
```

Analyser un fichier de mots de passe :
```bash
python3 passhash.py fichier mots_de_passe.txt
```

## Structure du projet

```
passhash-analyzer/
  |-- passhash.py        # Script principal avec toutes les fonctionnalites
  |-- requirements.txt   # Dependances Python
  |-- README.md          # Documentation du projet
```

## Avertissement ethique

Cet outil est strictement destine a un usage educatif. L'utilisation de techniques d'attaque par dictionnaire contre des systemes ou des hachages sans autorisation est illegale. Les demonstrations d'attaque sont simulees et ont pour but de comprendre les vulnerabilites afin de mieux s'en proteger. L'auteur decline toute responsabilite quant a l'utilisation abusive de cet outil.

## Licence

MIT License
