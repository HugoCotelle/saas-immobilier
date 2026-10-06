"""Génère la paire de clés qui identifie votre serveur auprès des services de
notification (Web Push). À lancer une seule fois :

    python3 generer_cles_vapid.py

Nécessite le paquet « cryptography » (pip install cryptography).
Copiez ensuite les trois lignes affichées dans les variables d'environnement
du serveur (Render). La clé privée est un secret : ne la partagez pas et ne la
mettez pas dans le code.
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def encoder(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode()


cle = ec.generate_private_key(ec.SECP256R1())
publique = cle.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
privee = cle.private_numbers().private_value.to_bytes(32, "big")

print("Variables à ajouter chez l'hébergeur du serveur (Render) :\n")
print(f"VAPID_PUBLIC_KEY={encoder(publique)}")
print(f"VAPID_PRIVATE_KEY={encoder(privee)}")
print("VAPID_SUBJECT=mailto:contact@zelyro.fr   (remplacez par une adresse de contact à vous)")
