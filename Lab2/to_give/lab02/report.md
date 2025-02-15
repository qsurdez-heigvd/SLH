# Questions SLH Lab #2 - Authentification Web

## 1. Différence de risque entre Passkeys et SSO

Les passkeys et le SSO présentent des modèles de risque fondamentalement différents, notamment dans leur architecture de sécurité.

Avec le SSO, nous reposons sur un point central de confiance - le fournisseur d'identité. Cette centralisation, bien que pratique, crée ce qu'on appelle un "single point of failure". Si un attaquant parvient à compromettre le compte principal (par exemple un compte Google utilisé pour le SSO), il obtient automatiquement accès à tous les services connectés via ce SSO. La compromission d'un seul point entraîne donc une cascade d'accès non autorisés.

Les passkeys adoptent une approche radicalement différente en s'appuyant sur la cryptographie asymétrique de manière décentralisée. Chaque service reçoit sa propre paire de clés unique, même si ces clés sont générées depuis le même appareil. Cette architecture présente deux avantages majeurs en termes de sécurité :

1. La compromission d'un service n'affecte que ce service spécifique, les autres restant protégés par leurs propres clés uniques
2. La clé privée ne quitte jamais l'appareil de l'utilisateur, réduisant considérablement la surface d'attaque potentielle

## 2. Validation et Stockage des Images

La sécurisation des uploads d'images nécessite une approche en plusieurs couches, tant au niveau de la validation que du stockage.

### Validation des Images

La validation doit s'effectuer à plusieurs niveaux pour assurer une sécurité maximale :

1. Validation du format :
    - Vérification stricte de l'extension (.jpg uniquement)
    - Validation du type MIME réel du fichier
    - Analyse des signatures de fichiers (magic numbers)

2. Contrôles de sécurité :
    - Limitation de la taille du fichier pour prévenir les attaques DoS
    - Vérification de l'intégrité de l'image JPEG
    - Nettoyage des métadonnées pour éviter les injections de code malveillant

### Stockage Sécurisé

Le stockage des images doit suivre plusieurs principes de sécurité :

1. Organisation :
    - Stockage dans un répertoire dédié hors de l'arborescence web
    - Configuration stricte des permissions système
    - Utilisation d'un système de nommage unique

2. Sécurité :
    - Normalisation des chemins d'accès
    - Validation des chemins pour prévenir la traversée de répertoire
    - Séparation claire entre stockage et accès public

## 3. Analyse de la Politique de Nommage des Fichiers

La politique actuelle de nommage (UUID-nom_original) présente plusieurs vulnérabilités potentielles qu'il convient d'adresser.

### Vulnérabilités Identifiées

1. Conservation du nom original :
    - Risque de fuite d'informations sensibles
    - Possibilité d'exploitation des caractères spéciaux
    - Problèmes potentiels d'encodage

2. Structure prévisible :
    - La combinaison UUID-nom peut faciliter certaines attaques
    - Risque de collision en cas de noms similaires

### Solution Proposée

Voici une approche plus sécurisée pour le nommage des fichiers :

```rust
let safe_filename = format!("{}.jpg", Uuid::new_v4().to_string());
```
