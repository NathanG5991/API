from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List
import jwt
import datetime
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Définir une clé secrète pour signer les tokens JWT
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

# Initialisation de l'application FastAPI
app = FastAPI()

# Configuration de la base de données SQLite
DATABASE_URL = "sqlite:///./ports.db"  # URL de la base de données SQLite
engine = create_engine(DATABASE_URL)  # Création de l'engine SQLAlchemy
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)  # Session pour la base de données
Base = declarative_base()  # Classe de base pour les modèles SQLAlchemy

# Modèle de base de données pour les ports
class PortDB(Base):
    __tablename__ = "ports"  # Nom de la table pour les ports
    id = Column(Integer, primary_key=True, index=True)  # ID du port
    name = Column(String, index=True)  # Nom du port
    port_number = Column(Integer, unique=True, index=True)  # Numéro du port (unique)
    protocol = Column(String)  # Protocole (TCP, UDP, etc.)

# Créer les tables de la base de données
Base.metadata.create_all(bind=engine)

# Ajouter les ports par défaut si la base est vide
def initialize_ports():
    db = SessionLocal()
    if db.query(PortDB).count() == 0:  # Si la table est vide
        default_ports = [  # Liste des ports par défaut à insérer
            {"name": "HTTP", "port_number": 80, "protocol": "TCP"},
            {"name": "HTTPS", "port_number": 443, "protocol": "TCP"},
            {"name": "FTP", "port_number": 21, "protocol": "TCP"},
            {"name": "SSH", "port_number": 22, "protocol": "TCP"},
            {"name": "DNS", "port_number": 53, "protocol": "UDP"},
            {"name": "SMTP", "port_number": 25, "protocol": "TCP"},
            {"name": "POP3", "port_number": 110, "protocol": "TCP"},
            {"name": "IMAP", "port_number": 143, "protocol": "TCP"}
        ]
        # Insertion des ports dans la base de données
        for port in default_ports:
            db.add(PortDB(**port))
        db.commit()
    db.close()

initialize_ports()  # Initialisation des ports par défaut

# Dépendance pour obtenir la session de base de données
def get_db():
    db = SessionLocal()  # Ouvrir une nouvelle session
    try:
        yield db  # Renvoie la session pour être utilisée dans les endpoints
    finally:
        db.close()  # Fermer la session après utilisation

# Modèle utilisateur (pour la création d'un utilisateur)
class User(BaseModel):
    username: str
    password: str

# Modèle d'authentification (réponse avec le token JWT)
class AuthResponse(BaseModel):
    access_token: str
    token_type: str

# Modèle pour un port réseau
class Order(BaseModel):
    name: str
    port_number: int
    protocol: str

# Modèle de réponse sans mot de passe (utilisé pour renvoyer les utilisateurs)
class UserResponse(BaseModel):
    username: str

    class Config:
        orm_mode = True  # Permet de convertir les objets ORM en modèles Pydantic

# Fonction pour créer un token JWT
def create_jwt_token(username: str):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token valide pendant 1 heure
    payload = {"sub": username, "exp": expiration_time}  # Payload avec l'utilisateur et l'expiration
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)  # Création du token JWT
    return token

# Fonction pour vérifier le token JWT
def get_token_from_params(token: str = Query(...)):
    try:
        # Décodage du token et vérification de son intégrité
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]  # Renvoie le nom d'utilisateur extrait du token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")  # Token expiré
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")  # Token invalide

# Gestion des utilisateurs fictifs (base de données en mémoire)
users_db = {}

# Endpoint pour créer un utilisateur
@app.post("/users", response_model=User)
def create_user(user: User):
    if user.username in users_db:  # Vérifie si le nom d'utilisateur existe déjà
        raise HTTPException(status_code=400, detail="Username already exists")
    users_db[user.username] = {"username": user.username, "password": user.password}
    return user

# Endpoint pour obtenir tous les utilisateurs (sans leur mot de passe)
@app.get("/users", response_model=List[UserResponse])
def get_users():
    # Renvoie une liste des utilisateurs sans leur mot de passe
    return [UserResponse(username=username) for username in users_db]

# Endpoint pour obtenir un utilisateur spécifique (avec token obligatoire)
@app.get("/users", response_model=UserResponse)
def get_user(username: str, token: str = Depends(get_token_from_params)):
    if username not in users_db:  # Vérifie si l'utilisateur existe
        raise HTTPException(status_code=404, detail="User not found")
    user_data = users_db[username]
    # On renvoie les informations sans le mot de passe
    return UserResponse(username=user_data["username"])

# Endpoint pour mettre à jour un utilisateur (avec token obligatoire)
@app.put("/users", response_model=User)
def update_user(username: str, user: User, token: str = Depends(get_token_from_params)):
    if username not in users_db:  # Vérifie si l'utilisateur existe
        raise HTTPException(status_code=404, detail="User not found")
    users_db[username] = {"username": user.username, "password": user.password}
    return users_db[username]

# Endpoint pour supprimer un utilisateur (avec token obligatoire)
@app.delete("/users")
def delete_user(username: str, token: str = Depends(get_token_from_params)):
    if username not in users_db:  # Vérifie si l'utilisateur existe
        raise HTTPException(status_code=404, detail="User not found")
    del users_db[username]  # Supprime l'utilisateur de la base de données en mémoire
    return {"detail": f"User {username} has been deleted"}

# Endpoint pour s'authentifier et obtenir un token JWT
@app.post("/authenticate", response_model=AuthResponse)
def Create_authenticate(user: User):
    if user.username not in users_db or users_db[user.username]["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")  # Vérification des identifiants
    token = create_jwt_token(user.username)  # Création du token
    return {"access_token": token, "token_type": "bearer"}  # Retourne le token

# Endpoint GET pour récupérer les informations de l'utilisateur authentifié (avec token obligatoire)
@app.get("/authenticate", response_model=User)
def get_authenticate_info(username: str = Depends(get_token_from_params)):
    if username not in users_db:  # Vérifie si l'utilisateur existe
        raise HTTPException(status_code=404, detail="User not found")
    return users_db[username]

# Endpoint PUT pour mettre à jour les informations de l'utilisateur authentifié (avec token obligatoire)
@app.put("/authenticate", response_model=User)
def update_authenticated_user(user: User, username: str = Depends(get_token_from_params)):
    if username not in users_db:  # Vérifie si l'utilisateur existe
        raise HTTPException(status_code=404, detail="User not found")
    users_db[username] = {"username": user.username, "password": user.password}
    return users_db[username]

# Endpoint DELETE pour supprimer l'utilisateur authentifié (avec token obligatoire)
@app.delete("/authenticate")
def delete_authenticated_user(username: str = Depends(get_token_from_params)):
    if username not in users_db:  # Vérifie si l'utilisateur existe
        raise HTTPException(status_code=404, detail="User not found")
    del users_db[username]  # Supprime l'utilisateur de la base de données en mémoire
    return {"detail": f"User {username} has been deleted"}

# CRUD sur les ports réseau (avec token obligatoire)

# Endpoint pour lister les ports (avec token obligatoire)
@app.get("/orders", response_model=List[Order])
def list_orders(db: Session = Depends(get_db), token: str = Depends(get_token_from_params)):
    return db.query(PortDB).all()  # Renvoie tous les ports de la base de données

# Endpoint pour creer un port (avec token obligatoire)
@app.post("/orders", response_model=Order)
def create_order(order: Order, db: Session = Depends(get_db), username: str = Depends(get_token_from_params)):
    if db.query(PortDB).filter(PortDB.port_number == order.port_number).first():  # Vérifie si le port existe déjà
        raise HTTPException(status_code=400, detail="Port already exists")
    new_port = PortDB(name=order.name, port_number=order.port_number, protocol=order.protocol)  # Crée un nouveau port
    db.add(new_port)
    db.commit()
    db.refresh(new_port)
    return new_port

# Endpoint pour modifier un port (avec token obligatoire)
@app.put("/orders/{port_number}", response_model=Order)
def update_order(port_number: int, updated_order: Order, db: Session = Depends(get_db), username: str = Depends(get_token_from_params)):
    port = db.query(PortDB).filter(PortDB.port_number == port_number).first()
    if not port:  # Vérifie si le port existe
        raise HTTPException(status_code=404, detail="Port not found")
    port.name = updated_order.name  # Mise à jour des données du port
    port.protocol = updated_order.protocol
    db.commit()
    db.refresh(port)
    return port

# Endpoint pour supprimer un port (avec token obligatoire)
@app.delete("/orders/{port_number}")
def delete_order(port_number: int, db: Session = Depends(get_db), username: str = Depends(get_token_from_params)):
    port = db.query(PortDB).filter(PortDB.port_number == port_number).first()
    if not port:  # Vérifie si le port existe
        raise HTTPException(status_code=404, detail="Port not found")
    db.delete(port)  # Supprime le port
    db.commit()
    return {"detail": f"Port {port_number} has been deleted"}

# Lancement de l'application avec Uvicorn (serveur ASGI)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
