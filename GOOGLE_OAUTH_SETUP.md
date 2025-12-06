# Configuration Google OAuth - Sign In with Google

Ce guide explique comment configurer l'authentification Google OAuth pour votre application bancaire.

## 📋 Prérequis

- Un compte Google
- Accès à [Google Cloud Console](https://console.cloud.google.com/)

## 🚀 Étapes de Configuration

### 1. Créer un Projet Google Cloud

1. Accédez à [Google Cloud Console](https://console.cloud.google.com/)
2. Cliquez sur le menu déroulant en haut à gauche
3. Cliquez sur **"Nouveau projet"**
4. Nommez votre projet (ex: "IRBank Authentication")
5. Cliquez sur **"Créer"**

### 2. Activer l'API Google Sign-In

1. Dans le menu latéral, allez dans **"API et services" → "Bibliothèque"**
2. Recherchez **"Google+ API"**
3. Cliquez sur **"Activer"**

### 3. Créer des Identifiants OAuth 2.0

1. Allez dans **"API et services" → "Identifiants"**
2. Cliquez sur **"+ CRÉER DES IDENTIFIANTS"** → **"ID client OAuth"**
3. Si demandé, configurez l'écran de consentement OAuth :
   - Type: **Externe**
   - Nom de l'application: **IRBank**
   - Email assistance utilisateur: votre email
   - Logo: (optionnel)
   - Domaine autorisé: `localhost`
   - Cliquez sur **"Enregistrer et continuer"**
   
4. Retournez dans **"Identifiants"** et créez l'ID client OAuth :
   - Type d'application: **Application Web**
   - Nom: **IRBank Web Client**
   
5. **Origines JavaScript autorisées** :
   ```
   http://localhost:8080
   http://127.0.0.1:5500
   http://localhost:5500
   ```

6. **URI de redirection autorisés** :
   ```
   http://localhost:8080
   http://127.0.0.1:5500
   http://localhost:5500
   ```

7. Cliquez sur **"Créer"**

### 4. Copier les Identifiants

1. Une fenêtre s'ouvre avec votre **Client ID** et **Client Secret**
2. Copiez ces valeurs

### 5. Configuration Backend (.env)

Ouvrez le fichier `backend/.env` et ajoutez :

```env
GOOGLE_CLIENT_ID=votre_client_id_ici.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=votre_client_secret_ici
```

### 6. Configuration Frontend (index.html)

Ouvrez `index.html` et remplacez :

```javascript
const GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID_HERE.apps.googleusercontent.com";
```

Par :

```javascript
const GOOGLE_CLIENT_ID = "votre_client_id_ici.apps.googleusercontent.com";
```

### 7. Installer les Dépendances Python

Dans le terminal (avec l'environnement virtuel activé) :

```bash
cd backend
pip install PyJWT google-auth
```

Ou réinstallez toutes les dépendances :

```bash
pip install -r requirements.txt
```

### 8. Relancer le Serveur

```bash
# Arrêtez le serveur (Ctrl+C)
# Puis relancez-le
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 🧪 Test de la Connexion Google

1. Ouvrez votre navigateur sur `http://localhost:8080/index.html`
2. Dans le panneau "Log in to your account", vous devriez voir un bouton **"Sign in with Google"**
3. Cliquez dessus
4. Sélectionnez votre compte Google
5. Autorisez l'application
6. Vous serez automatiquement connecté et redirigé vers le dashboard

## 🔒 Fonctionnement

### Flux d'Authentification

1. L'utilisateur clique sur "Sign in with Google"
2. Google affiche une popup de sélection de compte
3. L'utilisateur sélectionne son compte et autorise l'application
4. Google renvoie un **JWT token** contenant :
   - `email` : Email de l'utilisateur
   - `name` : Nom complet
   - `sub` : ID Google unique
   - `picture` : URL de la photo de profil

5. Le frontend envoie ce token au backend (`/api/auth/google`)
6. Le backend décode le token et :
   - Vérifie si l'utilisateur existe (par email)
   - Si oui : connecte l'utilisateur
   - Si non : crée automatiquement un compte utilisateur

7. L'utilisateur est connecté **sans MFA** (car authentifié par Google)
8. Redirection vers le dashboard

## 📊 Données Stockées

Pour un utilisateur connecté via Google, le système stocke :

- `email` : Email Google
- `full_name` : Nom complet Google
- `username` : Généré automatiquement (email sans @domain + nombre aléatoire)
- `password` : UUID aléatoire chiffré (l'utilisateur ne l'utilisera jamais)
- `google_id` : ID Google unique pour identifier les connexions Google
- `balance` : 0.0 par défaut
- `role` : USER par défaut

## 🛡️ Sécurité

### Avantages
- ✅ Pas besoin de gérer les mots de passe
- ✅ Authentification déléguée à Google (hautement sécurisé)
- ✅ MFA géré par Google (si activé sur le compte utilisateur)
- ✅ Mise à jour automatique des informations de profil

### Points d'Attention
- ⚠️ En production, utilisez HTTPS obligatoirement
- ⚠️ Vérifiez toujours la signature du JWT Google (actuellement désactivée pour dev)
- ⚠️ Limitez les domaines autorisés dans Google Cloud Console
- ⚠️ Ne partagez jamais votre Client Secret

## 🔧 Dépannage

### Erreur "redirect_uri_mismatch"
➡️ Vérifiez que l'URI de votre frontend est bien ajoutée dans Google Cloud Console

### Bouton Google ne s'affiche pas
➡️ Vérifiez que le script Google est bien chargé :
```html
<script src="https://accounts.google.com/gsi/client" async defer></script>
```

### Erreur "Invalid Google token"
➡️ Vérifiez que PyJWT est installé : `pip install PyJWT`

### L'utilisateur n'est pas créé
➡️ Vérifiez les logs du serveur FastAPI dans le terminal

## 📚 Ressources

- [Documentation Google Sign-In](https://developers.google.com/identity/gsi/web)
- [Google Cloud Console](https://console.cloud.google.com/)
- [OAuth 2.0 Guide](https://developers.google.com/identity/protocols/oauth2)

## 🎯 Résumé

Une fois configuré, vos utilisateurs peuvent :
1. Se connecter avec leur compte Google en 1 clic
2. Éviter de créer/mémoriser un mot de passe
3. Bénéficier de la sécurité Google (2FA, détection d'activité suspecte, etc.)
4. Avoir un compte automatiquement créé lors de la première connexion

**Note** : Cette fonctionnalité est optionnelle. Les utilisateurs peuvent toujours créer un compte classique avec email/mot de passe.
