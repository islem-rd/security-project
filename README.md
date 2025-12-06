# Application Bancaire Sécurisée

Une application bancaire complète avec sécurité de niveau entreprise implémentant plusieurs algorithmes cryptographiques, contrôle d'accès basé sur les rôles et mécanismes d'authentification complets.

## Aperçu

Il s'agit d'une plateforme bancaire web moderne qui fournit des services financiers sécurisés avec un accent sur la protection des données, la confidentialité des utilisateurs et une authentification robuste. L'application prend en charge plusieurs rôles d'utilisateurs (Utilisateurs, Employés, Administrateurs) et implémente diverses couches de sécurité pour protéger les données financières sensibles.

## Fonctionnalités Principales

- **Système Multi-Rôles** : Interfaces séparées pour les clients, les employés et les administrateurs
- **Transactions Sécurisées** : Transfert de fonds entre comptes avec historique complet des transactions
- **Gestion des Comptes** : Créer et gérer plusieurs comptes bancaires avec suivi du solde en temps réel
- **Tableau de Bord Employé** : Interface du personnel pour gérer les clients et visualiser les analyses du système
- **Panneau de Contrôle Admin** : Système IAM complet avec gestion des utilisateurs et attribution des rôles
- **Intégration de Paiement** : Intégration Stripe pour le traitement sécurisé des paiements
- **Système de Messagerie** : Communication cryptée entre les utilisateurs et le personnel de la banque
- **Personnalisation du Profil** : Sélection d'avatar alimentée par Unsplash

## Aspects de Sécurité

### 1. **Authentification Multi-Facteurs (2FA/MFA)**
- Codes de vérification par email pour la connexion
- Codes à 6 chiffres limités dans le temps (expiration de 10 minutes)
- Codes à usage unique avec invalidation automatique
- Mode débogage pour les tests de développement
- Livraison d'emails cryptée SSL/TLS
- **Connexion Google OAuth** : Authentification sécurisée via compte Google (optionnel)

### 2. **Normes de Chiffrement Avancées**

#### **Chiffrement AES**
- Chiffrement AES 256 bits pour les données sensibles
- Stockage sécurisé des clés dans les variables d'environnement
- Utilisé pour chiffrer les numéros de compte et les détails des transactions

#### **Chiffrement RSA**
- Cryptographie à clé publique pour l'échange sécurisé de clés
- Chiffrement asymétrique pour les communications sensibles
- Signatures numériques pour la vérification des transactions

#### **Chiffre de Vigenère**
- Chiffrement classique pour l'obscurcissement supplémentaire des données
- Clés de chiffrement configurables
- Implémentation du chiffre de substitution polyalphabétique

#### **Chiffre de César**
- Chiffrement par substitution simple pour les données non critiques
- Valeurs de décalage configurables
- Implémentation éducative de la cryptographie classique

#### **Chiffrement d'Images**
- Chiffrement sécurisé des avatars et documents
- Protection des données binaires
- Stockage crypté des images de profil utilisateur

### 3. **Contrôle d'Accès Basé sur les Rôles (RBAC/IAM)**
- Système de rôles à trois niveaux : USER, EMPLOYEE, ADMIN
- Gestion granulaire des permissions
- Capacités de blocage/déblocage des utilisateurs
- Contrôle d'accès aux endpoints basé sur les rôles
- Authentification basée sur les sessions avec tokens JWT
- Tableau de bord IAM réservé aux administrateurs

### 4. **Prévention des Injections SQL**
- Requêtes paramétrées utilisant SQLAlchemy ORM
- Validation et assainissement des entrées
- Instructions préparées pour toutes les opérations de base de données
- Aucune concaténation directe de chaînes SQL

### 5. **Sécurité des Mots de Passe**
- Hachage Bcrypt avec sel (12 rounds)
- Exigences de force du mot de passe :
  - Minimum 8 caractères
  - Au moins 1 lettre majuscule
  - Au moins 1 symbole spécial
- Réinitialisation sécurisée du mot de passe avec codes de vérification
- Récupération de mot de passe basée sur le nom d'utilisateur

### 6. **Gestion des Sessions**
- **SQLAlchemy ORM** : Gestion des sessions de base de données avec `sessionmaker` et `Session`
- **Session scope** : Utilisation du pattern Dependency Injection avec `get_db()` pour créer et fermer automatiquement les sessions
- **FastAPI Sessions** : Sessions HTTP gérées automatiquement par FastAPI pour chaque requête
- **Isolation des transactions** : Chaque requête API utilise sa propre session DB avec commit/rollback automatique
- **Protection des ressources** : Vérification de l'identité utilisateur avant accès aux données (`user_id`, `role`)

### 7. **Protection des Données**
- **Chiffrement AES-256 (Mode CBC)** : 
  - Mots de passe stockés avec `aes_encrypt()` et déchiffrés avec `aes_decrypt()`
  - Utilisation d'un vecteur d'initialisation (IV) aléatoire pour chaque chiffrement
  - Clé de 32 octets stockée dans `AES_SECRET_KEY` (variables d'environnement)
  
- **Chiffrement Hybride RSA+AES** :
  - Images d'avatar chiffrées avec `hybrid_encrypt_image()`
  - Génération d'une clé de session AES (32 bytes) pour chaque image
  - La clé de session est chiffrée avec RSA-2048 public key
  - Déchiffrement avec `hybrid_decrypt_image()` utilisant la clé privée RSA

- **Validation des Entrées** :
  - `validate_email()` : Vérification du format email avec regex
  - `validate_password()` : Minimum 8 caractères, 1 majuscule, 1 symbole spécial
  - Assainissement des numéros de carte : suppression des espaces/tirets

- **Gestion Sécurisée des Variables d'Environnement** :
  - Chargement avec `load_dotenv()` depuis fichier `.env`
  - Clés sensibles : `AES_SECRET_KEY`, `GOOGLE_APP_PASSWORD`, `STRIPE_SECRET_KEY`, etc.
  - Aucune clé hardcodée dans le code source

### 8. **Sécurité des Emails**
- Gmail SMTP avec mots de passe spécifiques aux applications
- Chiffrement TLS/SSL pour la transmission des emails
- Livraison sécurisée des codes de vérification
- Aucune donnée sensible dans le corps des emails

## Stack Technologique

### Backend
- **Framework** : FastAPI (Python)
- **Base de Données** : SQLite avec SQLAlchemy ORM
- **Authentification** : Tokens JWT, hachage de mot de passe bcrypt
- **Email** : FastMail avec Gmail SMTP
- **Paiement** : Intégration API Stripe
- **Cryptographie** : PyCryptodome, bibliothèque cryptography

### Frontend
- **Technologie** : JavaScript Vanilla (ES6+)
- **Stylisation** : CSS personnalisé avec design glass morphism
- **Thème** : Palette de couleurs turquoise/noir
- **Polices** : Famille de polices Inter
- **UI/UX** : Design responsive avec dialogues modaux

## Installation

### Prérequis
- Python 3.8+
- pip (gestionnaire de paquets Python)
- Environnement virtuel (recommandé)

### Instructions d'Installation

1. **Cloner le dépôt**

2. **Configurer l'environnement virtuel Python**

**Windows (PowerShell) :**
```powershell
.\setup_venv.bat
# Ou manuellement :
python -m venv backend\venv
.\backend\venv\Scripts\Activate.ps1
```

**Linux/Mac :**
```bash
./setup_venv.sh
# Ou manuellement :
python3 -m venv backend/venv
source backend/venv/bin/activate
```

3. **Installer les dépendances**
```bash
cd backend
pip install -r requirements.txt
```

4. **Configurer les variables d'environnement**

Créer un fichier `.env` dans le répertoire `backend` avec :
```env
STRIPE_SECRET_KEY=your_stripe_secret_key
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
UNSPLASH_ACCESS_KEY=your_unsplash_access_key
VIGENERE_KEY=your_vigenere_key
CESAR_KEY=5
AES_SECRET_KEY=your_32_byte_secret_key
MFA_DEBUG_MODE=false
GOOGLE_EMAIL=your_email@gmail.com
GOOGLE_APP_PASSWORD=your_google_app_password
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

**Configuration Google OAuth (optionnel) :**

Pour activer la connexion Google, suivez ces étapes :

1. Accédez à [Google Cloud Console](https://console.cloud.google.com/)
2. Créez un nouveau projet ou sélectionnez un projet existant
3. Activez "Google+ API" dans la bibliothèque d'API
4. Créez des identifiants OAuth 2.0 :
   - Type: Application Web
   - Origines JavaScript autorisées: `http://localhost:8080`, `http://127.0.0.1:5500`
   - URI de redirection autorisés: `http://localhost:8080`, `http://127.0.0.1:5500`
5. Copiez le Client ID et Client Secret dans votre fichier `.env`
6. Dans `index.html`, remplacez `YOUR_GOOGLE_CLIENT_ID_HERE` par votre Client ID

5. **Initialiser la base de données**

6. **Démarrer le serveur**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

L'application sera disponible sur `http://localhost:8000`

## Lancement Rapide du Projet

### Méthode 1 : Utilisation des Scripts Automatiques

**Windows :**
```powershell
# 1. Lancer l'environnement virtuel et le serveur
.\launch_venv.bat
```

**Linux/Mac :**
```bash
# 1. Rendre le script exécutable (première fois uniquement)
chmod +x backend/launch_venv.sh

# 2. Lancer le serveur
cd backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Méthode 2 : Lancement Manuel

**Windows (PowerShell) :**
```powershell
# 1. Activer l'environnement virtuel
.\backend\venv\Scripts\Activate.ps1

# 2. Naviguer vers le backend
cd backend

# 3. Démarrer le serveur FastAPI
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Linux/Mac :**
```bash
# 1. Activer l'environnement virtuel
source backend/venv/bin/activate

# 2. Naviguer vers le backend
cd backend

# 3. Démarrer le serveur FastAPI
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Accès à l'Application

Une fois le serveur démarré :
- **Backend API** : `http://localhost:8000`
- **Documentation API** : `http://localhost:8000/docs`

**Lancer l'Interface Utilisateur :**

**Option 1 : Serveur HTTP Python Simple**

**Windows/Linux/Mac :**
```bash
# Dans le répertoire racine du projet
python -m http.server 8080
```

Accès : `http://localhost:8080/index.html`

**Option 2 : Live Server (VS Code Extension)**
```bash
# Installer l'extension Live Server dans VS Code
# Puis clic-droit sur index.html → "Open with Live Server"
```

Accès : `http://127.0.0.1:5500/index.html`

**Option 3 : Serveur**
```bash
# Installer http-server globalement
python -m http.server 8080
```

Accès : `http://localhost:8080/index.html`

### Arrêt du Serveur

- Appuyez sur `Ctrl+C` dans le terminal pour arrêter le serveur
- Tapez `deactivate` pour sortir de l'environnement virtuel

## Utilisation

### Comptes de Test Par Défaut

Après l'exécution de `create_test_data.py`, vous aurez :

**Compte Administrateur :**
- Nom d'utilisateur : admin
- Email : admin@irbank.com
- Mot de passe : Admin123!

**Compte Employé :**
- Nom d'utilisateur : employee1
- Email : employee1@irbank.com
- Mot de passe : Emp123!

**Compte Utilisateur :**
- Nom d'utilisateur : user1
- Email : user1@example.com
- Mot de passe : User123!

### Interfaces Principales

1. **Page de Connexion** (`index.html`)
   - Portail d'authentification principal
   - Vérification MFA
   - Lien de mot de passe oublié

2. **Tableau de Bord Utilisateur** (`dashboard.html`)
   - Vue d'ensemble du compte
   - Gestion des transactions
   - Transferts de fonds
   - Paramètres de profil

3. **Panneau Employé** (`employee.html`)
   - Gestion des clients
   - Surveillance des transactions
   - Gestion des tickets de support

4. **IAM Administrateur** (`employee-iam.html`)
   - Gestion des rôles utilisateur
   - Blocage/déblocage de compte
   - Création de compte employé
   - Administration système

5. **Réinitialisation de Mot de Passe** (`reset-password.html`)
   - Récupération basée sur le nom d'utilisateur
   - Codes de vérification par email
   - Mise à jour sécurisée du mot de passe

## Points de Terminaison API

### Authentification
- `POST /api/users/register` - Créer un nouveau compte utilisateur
- `POST /api/users/login` - Connexion utilisateur avec MFA
- `POST /api/users/verify-mfa` - Vérifier le code MFA
- `POST /api/auth/google` - Connexion avec compte Google (OAuth)
- `POST /api/forgot-password` - Demander un code de réinitialisation de mot de passe
- `POST /api/reset-password` - Réinitialiser le mot de passe avec code de vérification

### Gestion des Comptes
- `GET /api/accounts` - Obtenir les comptes utilisateur
- `POST /api/accounts` - Créer un nouveau compte
- `GET /api/accounts/{account_id}/balance` - Vérifier le solde

### Transactions
- `POST /api/transactions/transfer` - Transférer des fonds
- `GET /api/transactions/history` - Historique des transactions

### Opérations Administrateur
- `POST /admin/block-user` - Bloquer un compte utilisateur
- `POST /admin/unblock-user` - Débloquer un compte utilisateur
- `POST /admin/create-employee` - Créer un compte employé
- `GET /admin/users` - Lister tous les utilisateurs

## Meilleures Pratiques de Sécurité

### Pour le Déploiement

1. **Variables d'Environnement**
   - Ne jamais committer les fichiers `.env` dans le contrôle de version
   - Utiliser des clés fortes générées aléatoirement
   - Rotation régulière des secrets

2. **HTTPS Uniquement**
   - Déployer avec certificats SSL/TLS
   - Activer les en-têtes HSTS
   - Utiliser des cookies sécurisés

3. **Sécurité de la Base de Données**
   - Utiliser PostgreSQL ou MySQL en production (pas SQLite)
   - Activer le chiffrement de la base de données au repos
   - Sauvegardes automatisées régulières

4. **Surveillance**
   - Activer la journalisation d'audit
   - Surveiller les tentatives de connexion échouées
   - Mettre en place la détection d'intrusion

5. **Mises à Jour**
   - Maintenir les dépendances à jour
   - Correctifs de sécurité réguliers
   - Analyse des vulnérabilités

## Structure du Projet

```
code (1)/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── requirements.txt        # Python dependencies
│   ├── create_test_data.py    # Database initialization
│   ├── generate_keys.py       # Encryption key generator
│   ├── .env                   # Environment variables
│   └── venv/                  # Virtual environment
├── index.html                 # Login page
├── dashboard.html             # User dashboard
├── employee.html             # Employee interface
├── employee-iam.html         # Admin IAM panel
├── reset-password.html       # Password recovery
├── user-account.html         # Account management
├── user-messages.html        # User messaging
├── employee-account.html     # Employee profile
├── employee-messages.html    # Employee messaging
├── verification.html         # MFA verification
├── package.json              # Project metadata
└── README.md                 # This file
```

## Fichiers de Documentation

- `AUTHENTICATION_FLOW.md` - Processus d'authentification détaillé
- `GOOGLE_OAUTH_SETUP.md` - Configuration Google Sign-In (OAuth)
- `STRIPE_SETUP.md` - Guide d'intégration de paiement
- `UNSPLASH_SETUP.md` - Configuration de l'API d'avatar
- `LAUNCH.md` - Instructions de lancement
- `AVATAR_APIS.md` - Documentation du service d'avatar
- `README_TEST_DATA.md` - Informations sur les données de test

## Implémentations Cryptographiques

L'application implémente 8 aspects majeurs de sécurité :

1. ✅ **AES** - Advanced Encryption Standard pour le chiffrement des données
2. ✅ **2FA/SSL-TLS** - Authentification à deux facteurs avec transmission sécurisée
3. ✅ **Vigenère** - Chiffre polyalphabétique classique
4. ✅ **César** - Chiffre de substitution classique
5. ✅ **SQL** - Prévention des injections SQL
6. ✅ **Chiffrement d'Images** - Stockage sécurisé des images
7. ✅ **RSA** - Cryptographie à clé publique
8. ✅ **RBAC/IAM** - Contrôle d'accès basé sur les rôles & Gestion des identités

## Maintenance

### Réinitialisation de la Base de Données
```bash
# Windows
.\backend\reset_db.bat

# Linux/Mac
./backend/reset_db.sh
```

### Génération de Transactions de Test
```bash
cd backend
python test_transactions.py
```

## Contribution

Il s'agit d'un projet éducatif démontrant le développement d'une application bancaire sécurisée avec plusieurs implémentations cryptographiques et meilleures pratiques de sécurité.

## Licence

Ce projet est à des fins éducatives. Veuillez assurer la conformité avec les réglementations financières lors du déploiement en production.

## Support

Pour les problèmes ou questions sur les implémentations de sécurité, consultez les fichiers de documentation ou examinez les commentaires de code dans `backend/main.py`.

---

**⚠️ Avis de Sécurité** : Cette application implémente plusieurs couches de sécurité à des fins éducatives. Pour un déploiement en production, des mesures de sécurité supplémentaires, des audits de sécurité professionnels et la conformité avec les réglementations financières (PCI-DSS, RGPD, etc.) sont requis.

## Galerie / Screenshots

Voici un aperçu des interfaces et fonctionnalités de l'application :

### Interfaces Utilisateur & Employé
![Interface Bancaire](screenshots/Capture%20d'écran%202025-11-29%20224758.png)
![Tableau de Bord](screenshots/Capture%20d'écran%202025-11-29%20225142.png)
![Gestion de Compte](screenshots/Capture%20d'écran%202025-11-29%20225310.png)

### Fonctionnalités de Sécurité
![Authentification](screenshots/Capture%20d'écran%202025-11-29%20225429.png)
![Sécurité Avancée](screenshots/Capture%20d'écran%202025-11-29%20225603.png)
![Gestion des Rôles](screenshots/Capture%20d'écran%202025-11-29%20225702.png)

### Rapports et Audits
![Audit de Sécurité](screenshots/Capture%20d'écran%202025-12-01%20112356.png)
![Rapport de Vulnérabilité](screenshots/Capture%20d'écran%202025-12-01%20112427.png)
![Logs Système](screenshots/Capture%20d'écran%202025-12-01%20113459.png)
