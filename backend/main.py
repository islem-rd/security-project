from fastapi import FastAPI, HTTPException, Depends
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship, joinedload
from pydantic import BaseModel, ConfigDict
from enum import Enum
import random
from datetime import datetime, timedelta
import stripe
import os
from dotenv import load_dotenv
import uuid
import re
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
import json
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
ADMIN_USER_ID = 1
SYSTEM_SENDER_ID = 9999

load_dotenv()

# Azure RBAC - Role definitions
class Role(str, Enum):
    USER = "user"
    EMPLOYEE = "employee"
    ADMIN = "admin"

# Mots-clés à surveiller pour une injection SQL
SQL_INJECTION_KEYWORDS = [
    "' OR '1'='1",
    "UNION SELECT",
    "SELECT * FROM",
    "DROP TABLE",
    "; --",
    "SLEEP("
]


# --- Chargement des clés RSA ---
try:
    with open("public.pem", "rb") as f:
        RSA_PUBLIC_KEY = RSA.import_key(f.read())
    with open("private.pem", "rb") as f:
        RSA_PRIVATE_KEY = RSA.import_key(f.read())
except FileNotFoundError:
    print("⚠️ ATTENTION: Clés RSA non trouvées. Lancez generate_keys.py d'abord.")

def cesar(text: str, shift: int) -> str:
    result = []

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            offset = (ord(char) - base + shift) % 26
            result.append(chr(base + offset))
        else:
            # On laisse inchangés les caractères non alphabétiques
            result.append(char)

    return "".join(result)
def vigenere_encrypt(plain_text: str) -> str:
   
    encrypted_bytes = []
    key_length = len(os.getenv("VIGENERE_KEY"))
    
    for i, char in enumerate(plain_text):
        key_char = os.getenv("VIGENERE_KEY")[i % key_length]
        # Opération XOR
        encrypted_byte = ord(char) ^ ord(key_char)
        encrypted_bytes.append(encrypted_byte)
        
    # Retourne une chaîne de texte propre (ASCII) pour la BD
    return base64.b64encode(bytes(encrypted_bytes)).decode('utf-8')

def vigenere_decrypt(encrypted_text: str) -> str:
    """
    Déchiffre un texte chiffré avec vigenere_encrypt.
    """
    try:
        encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
        decrypted_chars = []
        key_length = len(os.getenv("VIGENERE_KEY"))
        
        for i, byte in enumerate(encrypted_bytes):
            key_char = os.getenv("VIGENERE_KEY")[i % key_length]
            # Opération XOR inverse
            decrypted_char = chr(byte ^ ord(key_char))
            decrypted_chars.append(decrypted_char)
            
        return "".join(decrypted_chars)
    except Exception as e:
        print(f"Erreur de déchiffrement : {e}")
        return None

AES_KEY_BYTES = os.getenv("AES_SECRET_KEY", "default_32_byte_secret_key_1234").encode('utf-8')
if len(AES_KEY_BYTES) != 32:
    raise ValueError("La clé AES_SECRET_KEY doit faire 32 octets de long")

def aes_encrypt(plain_text: str) -> str:
    """Chiffre un texte avec AES-256 (Mode CBC)."""
    try:
        # Crée un nouveau chiffreur avec un IV (vecteur d'initialisation) aléatoire
        cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC)
        
        # Prépare le texte (remplissage)
        padded_data = pad(plain_text.encode('utf-8'), AES.block_size)
        
        # Chiffre les données
        encrypted_data = cipher.encrypt(padded_data)
        
        # Nous devons sauvegarder l'IV avec le texte chiffré pour pouvoir le déchiffrer
        iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Format "IV:TexteChiffré"
        return f"{iv_b64}:{encrypted_b64}"
    except Exception as e:
        print(f"Erreur de chiffrement AES: {e}")
        return None

def aes_decrypt(encrypted_text: str) -> str:
    """Déchiffre un texte chiffré avec aes_encrypt."""
    try:
        # Sépare l'IV du texte chiffré
        iv_b64, encrypted_b64 = encrypted_text.split(':')
        
        iv = base64.b64decode(iv_b64)
        encrypted_data = base64.b64decode(encrypted_b64)
        
        # Crée le chiffreur avec la clé et l'IV sauvegardé
        cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, iv=iv)
        
        # Déchiffre et retire le "padding"
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Erreur de déchiffrement AES: {e}")
        # Retourne None si le déchiffrement échoue (ex: mauvais mot de passe -> mauvais padding)
        return None
    
def hybrid_encrypt_image(image_base64: str) -> str:
    """
    1. Génère une clé AES aléatoire (session key).
    2. Chiffre l'image avec cette clé AES.
    3. Chiffre la clé AES avec RSA Public Key.
    4. Retourne: Clé_AES_Chiffrée || :: || Image_Chiffrée
    """
    try:
        # 1. Générer une clé AES unique pour cette image (32 bytes)
        session_key = get_random_bytes(32)

        # 2. Chiffrer l'image avec cette clé AES (Mode CBC comme avant)
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        padded_data = pad(image_base64.encode('utf-8'), AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # On a besoin de l'IV pour déchiffrer l'AES plus tard
        iv = cipher_aes.iv

        # 3. Chiffrer la clé de session AES avec RSA
        cipher_rsa = PKCS1_OAEP.new(RSA_PUBLIC_KEY)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # 4. Tout encoder en Base64 pour le stockage
        # Format de stockage : CléAES_RSA + Separateur + IV + Separateur + Image_AES
        b64_enc_key = base64.b64encode(enc_session_key).decode('utf-8')
        b64_iv = base64.b64encode(iv).decode('utf-8')
        b64_data = base64.b64encode(encrypted_data).decode('utf-8')

        return f"{b64_enc_key}::{b64_iv}::{b64_data}"

    except Exception as e:
        print(f"Erreur Hybrid Encrypt: {e}")
        return None

def hybrid_decrypt_image(stored_data: str) -> str:
    """
    Inverse du processus :
    1. Sépare les données.
    2. Déchiffre la clé AES avec RSA Private Key.
    3. Déchiffre l'image avec la clé AES récupérée.
    """
    try:
        if "::" not in stored_data:
            return None # Format invalide

        b64_enc_key, b64_iv, b64_data = stored_data.split("::")

        # Décoder le base64
        enc_session_key = base64.b64decode(b64_enc_key)
        iv = base64.b64decode(b64_iv)
        encrypted_data = base64.b64decode(b64_data)

        # 1. Déchiffrer la clé AES avec RSA Privé
        cipher_rsa = PKCS1_OAEP.new(RSA_PRIVATE_KEY)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # 2. Déchiffrer l'image avec la clé AES récupérée
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher_aes.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, AES.block_size)

        return decrypted_data.decode('utf-8')

    except Exception as e:
        print(f"Erreur Hybrid Decrypt: {e}")
        return None
    
    
# Initialize FastAPI
app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def create_security_alert_message(db: Session, recipient_id: int, threat_details: str, threat_type: str = "SQL_INJECTION") -> dict:
    """
    Crée et chiffre un message d'alerte de sécurité dans la base de données.
    
    Système ATP (Advanced Threat Protection):
    - Détecte les tentatives d'injection SQL
    - Envoie des alertes chiffrées DIRECTEMENT à l'utilisateur concerné
    - Documente chaque tentative pour audit et analyse
    
    Args:
        db: Session de base de données
        recipient_id: ID de l'utilisateur destinataire (l'utilisateur qui a déclenché la menace)
        threat_details: Description détaillée de la menace
        threat_type: Type de menace (SQL_INJECTION, XSS, etc.)
    
    Returns:
        Dict avec le statut et les détails de l'alerte créée
    """
    try:
        try:
            recipient_id = int(recipient_id)
        except (ValueError, TypeError):
            print(f"⚠️ AVERTISSEMENT: recipient_id invalide: {recipient_id}")
            recipient_id = ADMIN_USER_ID
        
        subject = f"🚨 ALERTE SÉCURITÉ CRITIQUE - {threat_type}"
        content = f"""
╔════════════════════════════════════════════════════════════╗
║         ⚠️  TENTATIVE D'ATTAQUE DÉTECTÉE  ⚠️              ║
╚════════════════════════════════════════════════════════════╝

🛡️ SYSTÈME ANTI-MENACE (ATP) - Advanced Threat Protection

⏱️ Timestamp: {datetime.now().isoformat()}
🚫 Status: BLOQUÉE ET ENREGISTRÉE

Détails de la tentative détectée:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{threat_details}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ ACTION PRISE:
   • Votre requête a été identifiée comme potentiellement dangereuse
   • La requête a été BLOQUÉE et ne s'est pas exécutée
   • Cet incident a été enregistré et analysé
   • Les administrateurs de sécurité ont été notifiés

ℹ️ INFORMATIONS IMPORTANTES:
   • Si vous croyez que c'est une erreur, contactez le support
   • Ne pas repartager les détails de cette alerte
   • Vérifiez votre activité récente pour détecter un accès non autorisé

🔐 Ce message est chiffré et accessible uniquement par vous.
        """.strip()
        
        encrypted_subject = cesar(subject, int(os.getenv("CESAR_KEY", 3)))
        encrypted_content = cesar(content, int(os.getenv("CESAR_KEY", 3)))

        recipient = db.query(User).filter(User.id == recipient_id).first()
        if not recipient:
            print(f"⚠️ AVERTISSEMENT: Utilisateur {recipient_id} introuvable pour l'alerte de sécurité")
            # Envoyer à l'admin comme fallback
            recipient_id = ADMIN_USER_ID
            recipient = db.query(User).filter(User.id == recipient_id).first()
            if not recipient:
                return {
                    "status": "error",
                    "message": f"Aucun destinataire trouvé",
                    "threat_type": threat_type,
                    "action": "SECURITY_EVENT_LOGGED_NO_RECIPIENT"
                }

        new_alert = Message(
            message_id=str(uuid.uuid4()),
            sender_id=SYSTEM_SENDER_ID,  # Bot de sécurité système (9999)
            recipient_id=recipient_id,
            subject=encrypted_subject,
            content=encrypted_content,
            created_at=datetime.now(),
            is_security_alert=True
        )
        
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        
        alert_result = {
            "status": "success",
            "message_id": new_alert.message_id,
            "recipient_id": recipient_id,
            "threat_type": threat_type,
            "timestamp": datetime.now().isoformat(),
            "action": "BLOCKED_AND_ALERTED"
        }
        
        print(f"✅ ALERTE ENVOYÉE À L'UTILISATEUR: {threat_type}")
        print(f"   User ID: {recipient_id} | Message ID: {new_alert.message_id}")
        print(f"   Détails: {threat_details[:80]}...")
        
        return alert_result
        
    except Exception as e:
        print(f"❌ ERREUR CRÉATION ALERTE: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": str(e),
            "threat_type": threat_type,
            "action": "FALLBACK_SECURITY_MEASURE"
        }


#Simulation de la Détection des Menaces(azure sql defender) atp
@app.middleware("http")
async def threat_detection_middleware(request: Request, call_next):
    """
    🛡️ SYSTÈME ATP - Advanced Threat Protection (Simulation Azure SQL Defender)
    
    Fonction: Surveiller le trafic HTTP entrant pour détecter les injections SQL
    
    Mécanisme de détection:
    1. Scanne le corps de la requête (POST, PUT, PATCH)
    2. Scanne les paramètres URL (query params)
    3. Recherche les mots-clés SQL malveillants connus
    4. Bloque la requête et envoie une alerte DIRECTE à l'utilisateur en cas de match
    
    Actions en cas de menace:
    ✅ Récupère le user_id de la requête
    ✅ Crée un message d'alerte chiffré
    ✅ Envoie l'alerte DIRECTEMENT à l'utilisateur concerné
    ✅ Bloque la requête avec status 403
    ✅ Enregistre l'attaque pour audit
    """
    
    request_body = ""
    threat_detected = False
    threat_keyword = None
    client_ip = request.client.host if request.client else "UNKNOWN"
    user_id = None

    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body_bytes = await request.body()
            request_body = body_bytes.decode('utf-8')
            
            try:
                body_json = json.loads(request_body) if request_body else {}
                user_id = body_json.get("user_id")
                if user_id is not None:
                    try:
                        user_id = int(user_id)
                    except (ValueError, TypeError):
                        print(f"[v0] user_id conversion failed: {user_id}, resetting to None")
                        user_id = None
            except:
                pass
            
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive
            
        except Exception as e:
            print(f"⚠️ Erreur lecture corps requête: {e}")
            request_body = ""

    if not user_id:
        try:
            query_user_id = request.query_params.get("user_id")
            if query_user_id:
                user_id = int(query_user_id)
        except (ValueError, TypeError):
            user_id = None

    full_request_string = request_body + str(request.query_params)
    
    for keyword in SQL_INJECTION_KEYWORDS:
        if keyword.upper() in full_request_string.upper():
            threat_detected = True
            threat_keyword = keyword
            break
    
    if threat_detected:
        threat_details = f"Tentative injection SQL - Mot-clé: '{threat_keyword}' | IP: {client_ip} | Route: {request.url.path}"
        
        db = SessionLocal()
        try:
            target_user_id = user_id if user_id and isinstance(user_id, int) else ADMIN_USER_ID
            
            alert_result = create_security_alert_message(
                db=db,
                recipient_id=target_user_id,
                threat_details=threat_details,
                threat_type="SQL_INJECTION"
            )
            
            print(f"\n{'='*70}")
            print(f"🚨 MENACE BLOQUÉE PAR ATP")
            print(f"{'='*70}")
            print(f"📍 Client IP: {client_ip}")
            print(f"👤 Utilisateur: {target_user_id}")
            print(f"🎯 Route: {request.url.path}")
            print(f"⚠️ Mot-clé détecté: {threat_keyword}")
            print(f"✅ Alerte envoyée (Message ID: {alert_result.get('message_id', 'N/A')})")
            print(f"{'='*70}\n")
            
        except Exception as e:
            print(f"❌ Erreur envoi alerte: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            db.close()
        
        raise HTTPException(
            status_code=403,
            detail={
                "error": "REQUÊTE BLOQUÉE - Menace SQL Injection détectée",
                "threat_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "action_taken": "Requête rejetée | Alerte de sécurité envoyée",
                "message": "Une tentative d'attaque a été détectée et bloquée. Un message d'alerte de sécurité vous a été envoyé."
            }
        )

    response = await call_next(request)
    return response

#Simulation de l'Évaluation des Vulnérabilités(azure sql defender) va
@app.get("/api/security/vulnerability-report")
def get_vulnerability_report():
    """Simule le rapport d'évaluation des vulnérabilités de SQL Defender."""
    report = []

    # Règle VA 1 : Vérification des Clés de Chiffrement (Hybride RSA)
    # On vérifie si les clés privées et publiques existent
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        report.append({
            "severity": "High",
            "check": "Configuration RSA manquante",
            "recommendation": "Générer les paires de clés RSA (private.pem/public.pem)."
        })
    else:
        report.append({
            "severity": "Passed",
            "check": "Clés RSA hybrides disponibles.",
            "recommendation": "N/A"
        })

    # Règle VA 2 : Vérification de la clé AES (utilisée pour les mots de passe)
    aes_key = os.getenv("AES_SECRET_KEY")
    if not aes_key or len(aes_key) < 32:
        report.append({
            "severity": "High",
            "check": "Force de la clé AES faible",
            "recommendation": "S'assurer que AES_SECRET_KEY dans .env fait 32 caractères."
        })
    else:
        report.append({
            "severity": "Passed",
            "check": "Clé AES de force adéquate.",
            "recommendation": "N/A"
        })

    # Règle VA 3 : Vérification du chiffrement Vigenère (doit être chiffré)
    vigenere_key = os.getenv("VIGENERE_KEY")
    if not vigenere_key:
        report.append({
            "severity": "Medium",
            "check": "Clé Vigenère manquante",
            "recommendation": "Définir VIGENERE_KEY dans le fichier .env."
        })
    # Vous pourriez ajouter d'autres vérifications sur les tables ici (e.g., SELECT * FROM User WHERE password LIKE 'Password@123%')
    
    return {
        "status": "Audit Complete",
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities_found": sum(1 for item in report if item["severity"] in ["High", "Medium"]),
        "report": report
    }
    

# Stripe Configuration
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Unsplash API Configuration (for real person photos)
UNSPLASH_ACCESS_KEY = os.getenv("UNSPLASH_ACCESS_KEY", None)
UNSPLASH_API_URL = "https://api.unsplash.com"

# EMAIL CONFIG
conf = ConnectionConfig(
    MAIL_USERNAME = os.getenv("GOOGLE_EMAIL"),   
    MAIL_PASSWORD = os.getenv("GOOGLE_APP_PASSWORD"), 
    MAIL_FROM = os.getenv("GOOGLE_EMAIL"),     
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_PORT = 465,
    MAIL_STARTTLS = False,
    MAIL_SSL_TLS = True,
    USE_CREDENTIALS = True
)
MFA_DEBUG_MODE = os.getenv("MFA_DEBUG_MODE", "false").lower() == "true"

async def send_mfa_email(recipient: str, code: str, subject: str = "Your Login Verification Code") -> bool:
    """
    Send MFA code via email. Falls back to console logging if email is not configured.
    Returns True if email was sent successfully, False otherwise.
    """
    try:
        # Check if email credentials are configured
        if not os.getenv("GOOGLE_EMAIL") or not os.getenv("GOOGLE_APP_PASSWORD"):
            print(f"[INFO] Email not configured. MFA code for {recipient}: {code}")
            return False
        
        message = MessageSchema(
            subject=subject,
            recipients=[recipient],
            body=f"Your verification code is: {code}\n\nThis code expires in 3 minutes.\n\nDo not share this code with anyone.",
            subtype="plain",
        )
        
        fast_mail = FastMail(conf)
        await fast_mail.send_message(message)
        print(f"[INFO] MFA email sent successfully to {recipient}")
        return True
        
    except Exception as exc:
        print(f"[WARN] Unable to send MFA email to {recipient}: {exc}")
        print(f"[DEBUG] MFA CODE for {recipient}: {code}")
        return False


# Database Configuration
DATABASE_URL = "sqlite:///./irbank.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    username = Column(String, unique=True)
    password = Column(String)
    balance = Column(Float, default=0.0)
    salary = Column(Float, default=0.0)  # Monthly salary
    avatar_url = Column(String, nullable=True)  # URL de la photo de profil
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    google_id = Column(String, nullable=True, unique=True)  # Google OAuth ID
    
    # Azure RBAC
    role = Column(SQLEnum(Role), default=Role.USER)
    is_blocked = Column(Boolean, default=False)
    blocked_at = Column(DateTime, nullable=True)
    blocked_by = Column(Integer, nullable=True)  # Employee ID with admin role
    block_reason = Column(String, nullable=True)
    
    cards = relationship("CreditCard", back_populates="owner")
    transactions = relationship("Transaction", back_populates="user")
    credits = relationship("Credit", back_populates="user")

class Employee(Base):
    __tablename__ = "employees"
    
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String, unique=True, index=True)
    email = Column(String, index=True)  # Removed unique=True to allow duplicate emails
    full_name = Column(String)
    username = Column(String, unique=True)
    password = Column(String)
    department = Column(String)
    avatar_url = Column(String, nullable=True)  # URL de la photo de profil
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Azure RBAC - can be 'employee' or 'admin'
    role = Column(SQLEnum(Role), default=Role.EMPLOYEE)
    can_block_users = Column(Boolean, default=False)  # True for admin role
    can_manage_roles = Column(Boolean, default=False)  # True for admin role
    can_view_audit_logs = Column(Boolean, default=False)  # True for admin role
    
    messages = relationship("Message", back_populates="sender")

class CreditCard(Base):
    __tablename__ = "credit_cards"
    
    id = Column(Integer, primary_key=True, index=True)
    card_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    stripe_card_token = Column(String)
    card_number = Column(String)  # Last 4 digits only
    full_card_number = Column(String, nullable=True)  # Full 16-digit number (for testing only, not secure)
    cardholder_name = Column(String)
    expiry_date = Column(String)
    card_type = Column(String)  # visa, mastercard, etc
    balance = Column(Float, default=0.0)
    credit_limit = Column(Float, default=5000.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    owner = relationship("User", back_populates="cards")
    transactions = relationship("Transaction", back_populates="card")

class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    card_id = Column(Integer, ForeignKey("credit_cards.id"), nullable=True)
    merchant = Column(String)
    amount = Column(Float)
    transaction_type = Column(String)  # debit, credit, transfer
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="completed")  # pending, completed, failed
    
    user = relationship("User", back_populates="transactions")
    card = relationship("CreditCard", back_populates="transactions")

class Credit(Base):
    __tablename__ = "credits"
    
    id = Column(Integer, primary_key=True, index=True)
    credit_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    credit_type = Column(String)  # bonus, referral, promotion
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    used = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="credits")

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String, unique=True, index=True)
    sender_id = Column(Integer, ForeignKey("employees.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    subject = Column(String)
    content = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)
    is_security_alert = Column(Boolean, default=False)
    
    sender = relationship("Employee", back_populates="messages")
class MFA_Code(Base):
    __tablename__ = "mfa_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    code = Column(String)
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)

    user = relationship("User")

class EmployeeMFA_Code(Base):
    __tablename__ = "employee_mfa_codes"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    code = Column(String)
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)

    employee = relationship("Employee")

class PasswordResetCode(Base):
    __tablename__ = "password_reset_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    user_type = Column(String)  # 'user' or 'employee'
    code = Column(String)
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)

# Azure RBAC - Audit Log for tracking admin actions
# Create tables
Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Schemas
class UserCreate(BaseModel):
    email: str
    full_name: str
    username: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    user_id: str
    email: str
    full_name: str
    username: str
    balance: float
    salary: float = 0.0
    avatar_url: str | None = None
    role: str = "user"
    is_blocked: bool = False
    created_at: datetime

class EmployeeCreate(BaseModel):
    email: str
    full_name: str
    username: str
    password: str
    department: str

class EmployeeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    employee_id: str
    email: str
    full_name: str
    username: str
    department: str
    avatar_url: str | None = None
    role: str = "employee"
    can_block_users: bool = False
    can_manage_roles: bool = False
    can_view_audit_logs: bool = False

class CreditCardCreate(BaseModel):
    user_id: int
    cardholder_name: str
    card_number: str
    expiry_date: str
    cvv: str

class CreditCardResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    card_id: str
    card_number: str
    full_card_number: str | None = None
    cardholder_name: str
    expiry_date: str
    card_type: str
    balance: float
    credit_limit: float
    is_active: bool

class TransactionCreate(BaseModel):
    user_id: int
    card_id: int | None = None  # Optional - transaction can be created without a card
    merchant: str
    amount: float
    description: str
    transaction_type: str

class TransactionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    transaction_id: str
    transaction_type: str
    card_id: int | None = None
    merchant: str
    amount: float
    description: str
    timestamp: datetime
    status: str

class DashboardMetrics(BaseModel):
    balance: float
    salary: float
    spent_today: float
    cards_count: int
    transactions_count: int

class DashboardResponse(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    user: UserResponse
    cards: list[CreditCardResponse]
    transactions: list[TransactionResponse]
    metrics: DashboardMetrics

class MFACodeVerify(BaseModel):
    user_id: int
    code: str

class EmployeeMFACodeVerify(BaseModel):
    employee_id: int
    code: str

# Azure RBAC - Pydantic Schemas
class BlockUserRequest(BaseModel):
    user_id: int
    reason: str

class UnblockUserRequest(BaseModel):
    user_id: int

class AssignRoleRequest(BaseModel):
    entity_type: str  # "user" or "employee"
    entity_id: int
    new_role: str  # "user", "employee", or "admin"
    can_block_users: bool = False
    can_manage_roles: bool = False
    can_view_audit_logs: bool = False

class UserListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    user_id: str
    email: str
    full_name: str
    username: str
    balance: float
    role: str
    is_active: bool
    is_blocked: bool
    blocked_at: datetime | None = None
    block_reason: str | None = None
    created_at: datetime

class MFALoginResponse(BaseModel):
    message: str
    user_id: int
    debug_code: str | None = None

class EmployeeMFALoginResponse(BaseModel):
    message: str
    employee_id: int
    debug_code: str | None = None

class CreditCreate(BaseModel):
    user_id: int
    amount: float
    credit_type: str
    description: str

class CreditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    credit_id: str
    amount: float
    credit_type: str
    description: str
    created_at: datetime
    used: bool

class MessageCreate(BaseModel):
    sender_id: int
    recipient_id: int
    subject: str
    content: str

class ForgotPasswordRequest(BaseModel):
    username: str
    user_type: str  # 'user' or 'employee'

class ResetPasswordRequest(BaseModel):
    username: str
    user_type: str
    code: str
    new_password: str

class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    message_id: str
    subject: str
    content: str
    created_at: datetime
    is_read: bool


# Validation functions
def validate_email(email: str):
    """Validate email format"""
    if not email or '@' not in email:
        return False, "Email must contain @ symbol"
    # Basic email format validation
    email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_pattern, email):
        return False, "Please enter a valid email address"
    return True, ""

def validate_password(password: str):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one symbol (!@#$%^&* etc.)"
    return True, ""

# User Endpoints
@app.post("/api/users/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Validate email
    email_valid, email_error = validate_email(user.email)
    if not email_valid:
        raise HTTPException(status_code=400, detail=email_error)
    
    # Validate password
    password_valid, password_error = validate_password(user.password)
    if not password_valid:
        raise HTTPException(status_code=400, detail=password_error)
    
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    existing_username = db.query(User).filter(User.username == user.username).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    encrypted_password = aes_encrypt(user.password)
    if encrypted_password is None:
        raise HTTPException(status_code=500, detail="Erreur lors du chiffrement du mot de passe.")
    
    new_user = User(
        user_id=str(uuid.uuid4()),
        email=user.email,
        full_name=user.full_name,
        username=user.username,
        password=encrypted_password,  
        balance=1000.0  
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get("/api/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.avatar_url and "::" in user.avatar_url:
        try:
            decrypted_base64 = hybrid_decrypt_image(user.avatar_url)
            if decrypted_base64:
                user.avatar_url = f"data:image/png;base64,{decrypted_base64}"
        except Exception as e:
            print(f"Erreur affichage avatar: {e}")
            user.avatar_url = None
    return user

@app.get("/api/users")
def list_users(db: Session = Depends(get_db)):
    try:
        users = db.query(User).all()
        # S'assurer que avatar_url est None si non défini (pour compatibilité avec anciennes bases)
        for user in users:
            if not hasattr(user, 'avatar_url') or user.avatar_url is None:
                user.avatar_url = None
        return users
    except Exception as e:
        print(f"Error listing users: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error loading users: {str(e)}")


@app.post("/api/users/login")
async def login_user(login: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        (User.email == login.email) | (User.username == login.email)
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Azure RBAC - Check if user is blocked
    if user.is_blocked:
        blocked_date = user.blocked_at.strftime("%d/%m/%Y %H:%M") if user.blocked_at else "Unknown"
        raise HTTPException(
            status_code=403, 
            detail=f"Votre compte a été bloqué le {blocked_date}.\n\nRaison: {user.block_reason or 'Action administrative'}\n\nAccès refusé jusqu'au déblocage par un administrateur."
        )

    decrypted_db_password = aes_decrypt(user.password)
    if decrypted_db_password is None or decrypted_db_password != login.password:
        raise HTTPException(
            status_code=401, 
            detail="Invalid email/username or password"
        )
   

    code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=3)

    mfa = MFA_Code(
        user_id=user.id,
        code=code,
        expires_at=expires_at
    )
    db.add(mfa)
    db.commit()

    # Send code by email (async)
    await send_mfa_email(user.email, code, "Your Login Verification Code")

    return {
        "user_id": user.id,
        "role": user.role.value,
        "debug_code": code if MFA_DEBUG_MODE else None  # Only return debug code in debug mode
    }



@app.post("/api/users/verify-code")
def verify_user_code(verify_request: MFACodeVerify, db: Session = Depends(get_db)):
    """Verify MFA code for user login"""
    mfa = db.query(MFA_Code).filter(
        MFA_Code.user_id == verify_request.user_id,
        MFA_Code.code == verify_request.code,
        MFA_Code.is_used == False
    ).first()

    if not mfa:
        raise HTTPException(status_code=400, detail="Invalid code")

    if datetime.utcnow() > mfa.expires_at:
        raise HTTPException(status_code=400, detail="Code expired")

    mfa.is_used = True
    db.commit()

    user = db.query(User).filter(User.id == verify_request.user_id).first()
    return {
        "id": user.id,
        "user_id": user.user_id,
        "email": user.email,
        "full_name": user.full_name,
        "username": user.username,
        "balance": user.balance,
        "salary": user.salary,
        "avatar_url": user.avatar_url,
        "role": user.role.value,
        "is_blocked": user.is_blocked,
        "created_at": user.created_at
    }


# Google OAuth Login
class GoogleLoginRequest(BaseModel):
    credential: str  # JWT token from Google

@app.post("/api/auth/google")
async def google_login(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    """Authenticate user with Google OAuth token"""
    try:
        # Verify the Google token
        # Note: In production, use actual Google Client ID verification
        # For now, we'll decode the JWT manually
        import jwt
        
        # Decode without verification for demo (UNSAFE for production)
        decoded_token = jwt.decode(request.credential, options={"verify_signature": False})
        
        email = decoded_token.get('email')
        name = decoded_token.get('name')
        google_id = decoded_token.get('sub')
        
        if not email:
            raise HTTPException(status_code=400, detail="Email not found in Google token")
        
        # Check if user exists
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            # Create new user from Google account
            new_user_id = str(uuid.uuid4())[:8].upper()
            username = email.split('@')[0] + str(random.randint(100, 999))
            
            user = User(
                user_id=new_user_id,
                email=email,
                full_name=name or email.split('@')[0],
                username=username,
                password=aes_encrypt(str(uuid.uuid4())),  # Random password (user won't use it)
                balance=0.0,
                salary=0.0,
                role=Role.USER,
                google_id=google_id
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        
        # Check if user is blocked
        if user.is_blocked:
            blocked_date = user.blocked_at.strftime("%d/%m/%Y %H:%M") if user.blocked_at else "Unknown"
            raise HTTPException(
                status_code=403, 
                detail=f"Votre compte a été bloqué le {blocked_date}.\n\nRaison: {user.block_reason or 'Action administrative'}"
            )
        
        # Return user data directly (no MFA for Google OAuth)
        return {
            "id": user.id,
            "user_id": user.user_id,
            "email": user.email,
            "full_name": user.full_name,
            "username": user.username,
            "balance": user.balance,
            "salary": user.salary,
            "avatar_url": user.avatar_url,
            "role": user.role.value,
            "is_blocked": user.is_blocked,
            "created_at": user.created_at,
            "google_auth": True
        }
        
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid Google token")
    except Exception as e:
        print(f"Google OAuth error: {e}")
        raise HTTPException(status_code=500, detail=f"Google authentication failed: {str(e)}")


# User Update Endpoints
class UserUpdateEmail(BaseModel):
    email: str

class UserUpdateUsername(BaseModel):
    username: str

class UserUpdatePassword(BaseModel):
    password: str

class UserUpdateSalary(BaseModel):
    salary: float

@app.put("/api/users/{user_id}/email", response_model=UserResponse)
def update_user_email(user_id: int, update: UserUpdateEmail, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate email
    email_valid, email_error = validate_email(update.email)
    if not email_valid:
        raise HTTPException(status_code=400, detail=email_error)
    
    # Check if email is already taken by another user
    existing_user = db.query(User).filter(User.email == update.email, User.id != user_id).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user.email = update.email
    db.commit()
    db.refresh(user)
    return user

@app.put("/api/users/{user_id}/username", response_model=UserResponse)
def update_user_username(user_id: int, update: UserUpdateUsername, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not update.username or len(update.username.strip()) == 0:
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    
    # Check if username is already taken by another user
    existing_user = db.query(User).filter(User.username == update.username, User.id != user_id).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    user.username = update.username
    db.commit()
    db.refresh(user)
    return user

@app.put("/api/users/{user_id}/password", response_model=UserResponse)
def update_user_password(user_id: int, update: UserUpdatePassword, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate password
    password_valid, password_error = validate_password(update.password)
    if not password_valid:
        raise HTTPException(status_code=400, detail=password_error)
    
    user.password = update.password  # In production, hash this!
    db.commit()
    db.refresh(user)
    return user

@app.put("/api/users/{user_id}/salary", response_model=UserResponse)
def update_user_salary(user_id: int, update: UserUpdateSalary, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update.salary < 0:
        raise HTTPException(status_code=400, detail="Salary cannot be negative")
    
    user.salary = update.salary
    db.commit()
    db.refresh(user)
    return user

@app.get("/api/users/{user_id}/dashboard", response_model=DashboardResponse)
def get_user_dashboard(user_id: int, db: Session = Depends(get_db)):
    """
    Aggregate endpoint used by the account/dashboard pages to confirm that
    updates (salary, card numbers, transactions) are persisted in the DB.
    """
    user = (
        db.query(User)
        .options(joinedload(User.cards))
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    active_cards = [card for card in user.cards if card.is_active]
    
    transactions = (
        db.query(Transaction)
        .filter(Transaction.user_id == user_id)
        .order_by(Transaction.timestamp.desc())
        .limit(20)
        .all()
    )
    
    today = datetime.utcnow().date()
    spent_today = sum(
        abs(tx.amount or 0.0)
        for tx in transactions
        if tx.transaction_type == "debit" and tx.timestamp and tx.timestamp.date() == today
    )
    
    metrics = DashboardMetrics(
        balance=user.balance or 0.0,
        salary=user.salary or 0.0,
        spent_today=spent_today,
        cards_count=len(active_cards),
        transactions_count=len(transactions),
    )
    
    return DashboardResponse(
        user=user,
        cards=active_cards,
        transactions=transactions,
        metrics=metrics,
    )

# Employee Endpoints
@app.post("/api/employees/register", response_model=EmployeeResponse)
def register_employee(employee: EmployeeCreate, db: Session = Depends(get_db)):
    # Validate email
    email_valid, email_error = validate_email(employee.email)
    if not email_valid:
        raise HTTPException(status_code=400, detail=email_error)
    
    # Validate password
    password_valid, password_error = validate_password(employee.password)
    if not password_valid:
        raise HTTPException(status_code=400, detail=password_error)
    
    existing_employee = db.query(Employee).filter(Employee.email == employee.email).first()
    if existing_employee:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    existing_username = db.query(Employee).filter(Employee.username == employee.username).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    encrypted_password_vigenere = vigenere_encrypt(employee.password) 
    new_employee = Employee(
        employee_id=str(uuid.uuid4()),
        email=employee.email,
        full_name=employee.full_name,
        username=employee.username,
        password=encrypted_password_vigenere,
        department=employee.department
    )
    db.add(new_employee)
    db.commit()
    db.refresh(new_employee)
    return new_employee

@app.get("/api/employees")
def list_employees(db: Session = Depends(get_db)):
    employees = db.query(Employee).all()
    return employees

@app.post("/api/employees/login")
async def login_employee(login: LoginRequest, db: Session = Depends(get_db)):
    employee = db.query(Employee).filter(
        (Employee.email == login.email) | (Employee.username == login.email)
    ).first()

    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    decrypted_db_password = vigenere_decrypt(employee.password)
   
    if decrypted_db_password != login.password:
        raise HTTPException(status_code=401, detail="Invalid password")

    code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=3)

    mfa = EmployeeMFA_Code(
        employee_id=employee.id,
        code=code,
        expires_at=expires_at
    )
    db.add(mfa)
    db.commit()

    # Send code by email (async)
    await send_mfa_email(employee.email, code, "Employee Login Verification Code")

    return {
        "employee_id": employee.id,
        "role": employee.role.value,
        "debug_code": code if MFA_DEBUG_MODE else None  # Only return debug code in debug mode
    }



@app.post("/api/employees/verify-code")
def verify_employee_code(verify_request: EmployeeMFACodeVerify, db: Session = Depends(get_db)):
    """Verify MFA code for employee login"""
    mfa = db.query(EmployeeMFA_Code).filter(
        EmployeeMFA_Code.employee_id == verify_request.employee_id,
        EmployeeMFA_Code.code == verify_request.code,
        EmployeeMFA_Code.is_used == False
    ).first()

    if not mfa:
        raise HTTPException(status_code=400, detail="Invalid code")

    if datetime.utcnow() > mfa.expires_at:
        raise HTTPException(status_code=400, detail="Code expired")

    mfa.is_used = True
    db.commit()

    employee = db.query(Employee).filter(Employee.id == verify_request.employee_id).first()
    return {
        "id": employee.id,
        "employee_id": employee.employee_id,
        "email": employee.email,
        "full_name": employee.full_name,
        "username": employee.username,
        "department": employee.department,
        "avatar_url": employee.avatar_url,
        "role": employee.role.value,
        "can_block_users": employee.can_block_users,
        "can_manage_roles": employee.can_manage_roles,
        "can_view_audit_logs": employee.can_view_audit_logs,
        "created_at": employee.created_at
    }

# Employee Update Endpoints
class EmployeeUpdateUsername(BaseModel):
    username: str

class EmployeeUpdatePassword(BaseModel):
    password: str

@app.put("/api/employees/{employee_id}/username", response_model=EmployeeResponse)
def update_employee_username(employee_id: int, update: EmployeeUpdateUsername, db: Session = Depends(get_db)):
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    if not update.username or len(update.username.strip()) == 0:
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    
    # Check if username is already taken by another employee
    existing_employee = db.query(Employee).filter(Employee.username == update.username, Employee.id != employee_id).first()
    if existing_employee:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    employee.username = update.username
    db.commit()
    db.refresh(employee)
    return employee

@app.put("/api/employees/{employee_id}/password", response_model=EmployeeResponse)
def update_employee_password(employee_id: int, update: EmployeeUpdatePassword, db: Session = Depends(get_db)):
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Validate password
    password_valid, password_error = validate_password(update.password)
    if not password_valid:
        raise HTTPException(status_code=400, detail=password_error)
    
    employee.password = update.password  # In production, hash this!
    db.commit()
    db.refresh(employee)
    return employee

# Password Reset Endpoints
@app.post("/api/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Send password reset code via email"""
    username = request.username.strip()
    
    # Find user or employee by username and type
    if request.user_type == "user":
        user = db.query(User).filter(User.username == username).first()
        if not user:
            # Don't reveal if username exists for security
            return {"message": "If the username exists, a reset code has been sent"}
        entity = user
        email = user.email
    elif request.user_type == "employee":
        employee = db.query(Employee).filter(Employee.username == username).first()
        if not employee:
            return {"message": "If the username exists, a reset code has been sent"}
        entity = employee
        email = employee.email
    else:
        raise HTTPException(status_code=400, detail="Invalid user type")
    
    # Generate 6-digit code
    code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    # Store reset code with username
    reset_code = PasswordResetCode(
        email=username,  # Store username in email field
        user_type=request.user_type,
        code=code,
        expires_at=expires_at,
        is_used=False
    )
    db.add(reset_code)
    db.commit()
    
    # Send email
    email_sent = await send_mfa_email(
        recipient=email,
        code=code,
        subject="Password Reset Code - IRBank"
    )
    
    if MFA_DEBUG_MODE or not email_sent:
        return {
            "message": "Reset code generated",
            "debug_code": code,
            "expires_in_minutes": 10
        }
    
    return {"message": "If the username exists, a reset code has been sent"}

@app.post("/api/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using verification code"""
    username = request.username.strip()
    
    # Find valid reset code
    reset_code = db.query(PasswordResetCode).filter(
        PasswordResetCode.email == username,  # username is stored in email field
        PasswordResetCode.user_type == request.user_type,
        PasswordResetCode.code == request.code,
        PasswordResetCode.is_used == False
    ).first()
    
    if not reset_code:
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")
    
    if datetime.utcnow() > reset_code.expires_at:
        raise HTTPException(status_code=400, detail="Reset code has expired")
    
    # Validate new password
    password_valid, password_error = validate_password(request.new_password)
    if not password_valid:
        raise HTTPException(status_code=400, detail=password_error)
    
    # Update password
    if request.user_type == "user":
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.password = request.new_password
    elif request.user_type == "employee":
        employee = db.query(Employee).filter(Employee.username == username).first()
        if not employee:
            raise HTTPException(status_code=404, detail="Employee not found")
        employee.password = request.new_password
    else:
        raise HTTPException(status_code=400, detail="Invalid user type")
    
    # Mark code as used
    reset_code.is_used = True
    db.commit()
    
    return {"message": "Password reset successfully"}

# Credit Card Endpoints (Stripe Integration)
@app.post("/api/cards/create", response_model=CreditCardResponse)
def create_credit_card(card: CreditCardCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == card.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        # Determine card type
        sanitized_number = card.card_number.replace(" ", "").replace("-", "")
        if len(sanitized_number) != 16 or not sanitized_number.isdigit():
            raise HTTPException(status_code=400, detail="Card number must be exactly 16 digits")
        
        card_type = "visa" if sanitized_number.startswith("4") else "mastercard"
        last_four = sanitized_number[-4:]
        
        # Try to create Stripe token if API key is configured
        stripe_token = None
        if stripe.api_key:
            try:
                token = stripe.Token.create(
                    card={
                        "number": card.card_number,
                        "exp_month": int(card.expiry_date.split("/")[0]),
                        "exp_year": int(card.expiry_date.split("/")[1]),
                        "cvc": card.cvv,
                    }
                )
                stripe_token = token.id
            except stripe.error.CardError as e:
                raise HTTPException(status_code=400, detail=f"Card error: {str(e)}")
            except stripe.error.StripeError as e:
                # If Stripe is not properly configured, continue without token
                print(f"Warning: Stripe error (continuing without token): {str(e)}")
        else:
            print("Warning: STRIPE_SECRET_KEY not configured. Card will be saved without Stripe token.")
        
        new_card = CreditCard(
            card_id=str(uuid.uuid4()),
            user_id=card.user_id,
            stripe_card_token=stripe_token,
            card_number=last_four,
            full_card_number=sanitized_number,
            cardholder_name=card.cardholder_name,
            expiry_date=card.expiry_date,
            card_type=card_type,
            balance=0.0,
            credit_limit=5000.0
        )
        db.add(new_card)
        db.commit()
        db.refresh(new_card)
        return new_card
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating card: {str(e)}")

@app.get("/api/cards/user/{user_id}")
def get_user_cards(user_id: int, db: Session = Depends(get_db)):
    cards = db.query(CreditCard).filter(CreditCard.user_id == user_id).all()
    return cards

class CardUpdateNumber(BaseModel):
    full_card_number: str
    card_type: str | None = None  # Optional card type update

@app.put("/api/cards/{card_id}/number", response_model=CreditCardResponse)
def update_card_number(card_id: int, update: CardUpdateNumber, db: Session = Depends(get_db)):
    card = db.query(CreditCard).filter(CreditCard.id == card_id).first()
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    
    # Validate card number (16 digits)
    card_number = update.full_card_number.replace(' ', '').replace('-', '')
    if len(card_number) != 16 or not card_number.isdigit():
        raise HTTPException(status_code=400, detail="Card number must be exactly 16 digits")
    
    # Store full number and last 4 digits
    card.full_card_number = card_number
    card.card_number = card_number[-4:]  # Last 4 digits
    
    # Update card type if provided
    if update.card_type:
        valid_types = ["visa", "mastercard", "amex", "discover", "other"]
        if update.card_type.lower() in valid_types:
            card.card_type = update.card_type.lower()
        else:
            # Auto-detect card type based on first digit if invalid type provided
            if card_number.startswith("4"):
                card.card_type = "visa"
            elif card_number.startswith("5"):
                card.card_type = "mastercard"
            elif card_number.startswith("3"):
                card.card_type = "amex"
            else:
                card.card_type = "other"
    
    db.commit()
    db.refresh(card)
    return card

# Transaction Endpoints
@app.post("/api/transactions/create", response_model=TransactionResponse)
def create_transaction(transaction: TransactionCreate, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.id == transaction.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate transaction type
        if transaction.transaction_type not in ["debit", "credit", "transfer"]:
            raise HTTPException(status_code=400, detail="Invalid transaction type. Must be 'debit', 'credit', or 'transfer'")
        
        # Get card if card_id is provided
        card = None
        if transaction.card_id:
            card = db.query(CreditCard).filter(CreditCard.id == transaction.card_id).first()
            if not card:
                raise HTTPException(status_code=404, detail="Card not found")
            # Verify card belongs to user
            if card.user_id != transaction.user_id:
                raise HTTPException(status_code=403, detail="Card does not belong to this user")
        
        # Update balances based on transaction type
        if transaction.transaction_type == "debit":
            user.balance -= transaction.amount
            if card:
                card.balance -= transaction.amount
        elif transaction.transaction_type == "credit":
            user.balance += transaction.amount
            if card:
                card.balance += transaction.amount
        
        new_transaction = Transaction(
            transaction_id=str(uuid.uuid4()),
            user_id=transaction.user_id,
            card_id=transaction.card_id,
            merchant=transaction.merchant,
            amount=transaction.amount,
            transaction_type=transaction.transaction_type,
            description=transaction.description,
            status="completed"
        )
        db.add(new_transaction)
        db.commit()
        db.refresh(new_transaction)
        return new_transaction
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error creating transaction: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error creating transaction: {str(e)}")

@app.get("/api/transactions/user/{user_id}")
def get_user_transactions(user_id: int, db: Session = Depends(get_db)):
    try:
        transactions = db.query(Transaction).filter(Transaction.user_id == user_id).order_by(Transaction.timestamp.desc()).all()
        return transactions
    except Exception as e:
        print(f"Error fetching transactions for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error loading transactions: {str(e)}")

# Credit Endpoints
@app.post("/api/credits/add", response_model=CreditResponse)
def add_credit(credit: CreditCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == credit.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.balance += credit.amount
    
    new_credit = Credit(
        credit_id=str(uuid.uuid4()),
        user_id=credit.user_id,
        amount=credit.amount,
        credit_type=credit.credit_type,
        description=credit.description
    )
    db.add(new_credit)
    db.commit()
    db.refresh(new_credit)
    return new_credit

@app.get("/api/credits/user/{user_id}")
def get_user_credits(user_id: int, db: Session = Depends(get_db)):
    credits = db.query(Credit).filter(Credit.user_id == user_id).all()
    return credits

# Message Endpoints
@app.post("/api/messages/send", response_model=MessageResponse)
def send_message(message: MessageCreate, db: Session = Depends(get_db)):
    employee = db.query(Employee).filter(Employee.id == message.sender_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    user = db.query(User).filter(User.id == message.recipient_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    encrypted_subject = cesar(message.subject, int(os.getenv("CESAR_KEY")))
    encrypted_content = cesar(message.content, int(os.getenv("CESAR_KEY")))
    new_message = Message(
        message_id=str(uuid.uuid4()),
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        subject=encrypted_subject,   
        content=encrypted_content
    )
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    return new_message

@app.get("/api/messages/user/{user_id}")
def get_user_messages(user_id: int, db: Session = Depends(get_db)):
    from sqlalchemy.orm import joinedload
    messages = db.query(Message).options(joinedload(Message.sender)).filter(Message.recipient_id == user_id).order_by(Message.created_at.desc()).all()
    for msg in messages:
        
        msg.subject = cesar(msg.subject, -int(os.getenv("CESAR_KEY")))
        msg.content = cesar(msg.content, -int(os.getenv("CESAR_KEY")))
    return messages

@app.put("/api/messages/{message_id}/read")
def mark_message_read(message_id: int, db: Session = Depends(get_db)):
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    message.is_read = True
    db.commit()
    return message

# Root endpoint
@app.get("/")
def root():
    return {
        "message": "IRBank API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/health",
        "endpoints": {
            "users": "/api/users",
            "employees": "/api/employees",
            "cards": "/api/cards",
            "transactions": "/api/transactions",
            "messages": "/api/messages"
        }
    }

# Avatar/Photo Endpoints
@app.get("/api/avatar/generate")
def generate_avatar(name: str = None, seed: str = None):
    """
    Génère une URL d'avatar avec photo de personne réelle
    Utilise Unsplash API si disponible, sinon RandomUser.me (gratuit)
    """
    import requests
    import hashlib
    
    # Si Unsplash API key est configurée, utiliser Unsplash
    if UNSPLASH_ACCESS_KEY:
        try:
            # Rechercher une photo de personne
            search_query = "portrait person" if not name else f"portrait {name}"
            response = requests.get(
                f"{UNSPLASH_API_URL}/search/photos",
                params={
                    "query": search_query,
                    "per_page": 1,
                    "orientation": "portrait"
                },
                headers={"Authorization": f"Client-ID {UNSPLASH_ACCESS_KEY}"},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("results") and len(data["results"]) > 0:
                    # Utiliser le seed pour avoir une photo cohérente
                    seed_hash = int(hashlib.md5((seed or name or "default").encode()).hexdigest(), 16)
                    photo_index = seed_hash % len(data["results"])
                    photo = data["results"][photo_index]
                    return {
                        "avatar_url": photo["urls"]["small"],
                        "source": "unsplash"
                    }
        except Exception as e:
            print(f"Unsplash API error: {e}")
    
    # Fallback: RandomUser.me (gratuit, pas besoin de clé API)
    try:
        seed_value = seed or name or "default"
        # Utiliser le seed pour générer un utilisateur cohérent
        seed_hash = hashlib.md5(seed_value.encode()).hexdigest()[:8]
        response = requests.get(
            f"https://randomuser.me/api/?seed={seed_hash}&inc=picture",
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return {
                    "avatar_url": data["results"][0]["picture"]["large"],
                    "source": "randomuser"
                }
    except Exception as e:
        print(f"RandomUser API error: {e}")
    
    # Fallback final: UI Avatars
    encoded_name = (name or "User").replace(" ", "+")
    return {
        "avatar_url": f"https://ui-avatars.com/api/?name={encoded_name}&size=128&background=random&color=fff&bold=true&format=png",
        "source": "ui-avatars"
    }

@app.post("/api/users/{user_id}/avatar")
def set_user_avatar(user_id: int, db: Session = Depends(get_db)):
    """Génère et assigne un avatar à un utilisateur"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Générer un avatar
    avatar_data = generate_avatar(user.full_name or user.username, user.email or str(user.id))
    temp_url= avatar_data["avatar_url"]
    
    try:
        # 3. Télécharger l'image depuis l'URL générée
        response = requests.get(temp_url, timeout=10)
        
        if response.status_code == 200:
            # 4. Convertir les octets de l'image en chaîne Base64
            image_base64 = base64.b64encode(response.content).decode('utf-8')
            
            # 5. Chiffrer cette chaîne avec le chiffrement Hybride (RSA + AES)
            # Assurez-vous que la fonction hybrid_encrypt_image est bien définie dans main.py
            encrypted_data = hybrid_encrypt_image(image_base64)
            
            if encrypted_data is None:
                raise HTTPException(status_code=500, detail="Échec du chiffrement de l'image")
            
            # 6. Sauvegarder la donnée chiffrée dans la base de données
            user.avatar_url = encrypted_data
            
            db.commit()
            db.refresh(user)
            
            return {
                "user_id": user_id,
                "message": "Avatar généré et chiffré avec succès",
                "source": avatar_data["source"]
            }
        else:
            print(f"Erreur téléchargement image: Status {response.status_code}")
            raise HTTPException(status_code=400, detail="Impossible de télécharger l'image source")
            
    except Exception as e:
        print(f"Erreur process avatar: {e}")
        # En cas d'erreur critique, on annule tout
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erreur lors du traitement de l'avatar: {str(e)}")

@app.post("/api/employees/{employee_id}/avatar")
def set_employee_avatar(employee_id: int, db: Session = Depends(get_db)):
    """Génère et assigne un avatar à un employé"""
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Générer un avatar
    avatar_data = generate_avatar(employee.full_name or employee.username, employee.email or str(employee.id))
    employee.avatar_url = avatar_data["avatar_url"]
    
    db.commit()
    db.refresh(employee)
    
    return {
        "employee_id": employee_id,
        "avatar_url": employee.avatar_url,
        "source": avatar_data["source"]
    }

# Admin IAM & RBAC Endpoints
@app.get("/admin/users")
def get_all_users(db: Session = Depends(get_db)):
    """Get all users for admin IAM dashboard"""
    users = db.query(User).all()
    users_list = []
    for user in users:
        users_list.append({
            "id": user.id,
            "user_id": user.user_id,
            "email": user.email,
            "full_name": user.full_name,
            "username": user.username,
            "role": user.role.value if isinstance(user.role, Role) else user.role,
            "balance": float(user.balance) if user.balance else 0.0,
            "is_blocked": user.is_blocked,
            "blocked_at": user.blocked_at.isoformat() if user.blocked_at else None,
            "blocked_by": user.blocked_by,
            "block_reason": user.block_reason,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "is_active": user.is_active
        })
    return {"users": users_list}

@app.get("/admin/employees")
def get_all_employees(db: Session = Depends(get_db)):
    """Get all employees for admin IAM dashboard"""
    employees = db.query(Employee).all()
    employees_list = []
    for emp in employees:
        employees_list.append({
            "id": emp.id,
            "employee_id": emp.employee_id,
            "email": emp.email,
            "full_name": emp.full_name,
            "username": emp.username,
            "department": emp.department,
            "role": emp.role.value if isinstance(emp.role, Role) else emp.role,
            "can_block_users": emp.can_block_users,
            "can_manage_roles": emp.can_manage_roles,
            "can_view_audit_logs": emp.can_view_audit_logs,
            "created_at": emp.created_at.isoformat() if emp.created_at else None,
            "is_active": emp.is_active
        })
    return {"employees": employees_list}

@app.post("/admin/block-user")
def block_user(request: BlockUserRequest, db: Session = Depends(get_db)):
    """Block a user account"""
    user = db.query(User).filter(User.id == request.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_blocked:
        raise HTTPException(status_code=400, detail="User is already blocked")
    
    # Get admin employee from session (for now, using a placeholder)
    # In production, you'd get this from authentication token
    admin_employee_id = 1  # Placeholder - should come from authenticated session
    
    user.is_blocked = True
    user.blocked_at = datetime.now()
    user.blocked_by = admin_employee_id
    user.block_reason = request.reason
    
    db.commit()
    
    return {"message": "User blocked successfully", "user_id": user.id}

@app.post("/admin/unblock-user")
def unblock_user(request: UnblockUserRequest, db: Session = Depends(get_db)):
    """Unblock a user account"""
    user = db.query(User).filter(User.id == request.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.is_blocked:
        raise HTTPException(status_code=400, detail="User is not blocked")
    
    # Get admin employee from session
    admin_employee_id = 1  # Placeholder
    
    previous_reason = user.block_reason
    user.is_blocked = False
    user.blocked_at = None
    user.blocked_by = None
    user.block_reason = None
    
    db.commit()
    
    return {"message": "User unblocked successfully", "user_id": user.id}

@app.post("/admin/assign-role")
def assign_role(request: AssignRoleRequest, db: Session = Depends(get_db)):
    """Assign role to user or employee"""
    admin_employee_id = 1  # Placeholder
    
    if request.entity_type == "user":
        entity = db.query(User).filter(User.id == request.entity_id).first()
        if not entity:
            raise HTTPException(status_code=404, detail="User not found")
        
        old_role = entity.role
        entity.role = Role[request.new_role.upper()]
        
    elif request.entity_type == "employee":
        entity = db.query(Employee).filter(Employee.id == request.entity_id).first()
        if not entity:
            raise HTTPException(status_code=404, detail="Employee not found")
        
        old_role = entity.role
        entity.role = Role[request.new_role.upper()]
        
        # Update permissions if admin role
        if request.new_role.lower() == "admin":
            entity.can_block_users = request.can_block_users if hasattr(request, 'can_block_users') else True
            entity.can_manage_roles = request.can_manage_roles if hasattr(request, 'can_manage_roles') else True
            entity.can_view_audit_logs = request.can_view_audit_logs if hasattr(request, 'can_view_audit_logs') else True
        else:
            entity.can_block_users = False
            entity.can_manage_roles = False
            entity.can_view_audit_logs = False
    
    else:
        raise HTTPException(status_code=400, detail="Invalid entity type")
    
    db.commit()
    return {"message": "Role assigned successfully"}

# Health Check
@app.get("/api/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
