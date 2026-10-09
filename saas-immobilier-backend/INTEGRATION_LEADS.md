# Réception des prospects LeBonCoin et SeLoger dans Zelyro

Zelyro n'utilise aucun accès non autorisé aux portails (pas de scraping) : les prospects arrivent par trois voies légitimes, que l'agence contrôle.

| Voie | Principe | Ce qu'il faut |
| --- | --- | --- |
| E-mail transféré | L'agence redirige les notifications SeLoger et LeBonCoin vers son adresse de réception Zelyro (page Compte). | Domaine de réception (Brevo Inbound Parsing) et variable EMAIL_INBOUND_SECRET sur le serveur. |
| Gmail connecté | Zelyro lit en lecture seule les messages des portails. | GOOGLE_CLIENT_ID et GOOGLE_CLIENT_SECRET, application Google vérifiée pour ce droit de lecture. |
| API partenaire | Une passerelle (Ubiflow...), un CRM ou Zapier envoie les prospects avec une clé propre à l'agence. | Rien côté serveur : l'administrateur de l'agence crée la clé dans Compte, « Connexion par API ». |

Dans tous les cas, la page Compte affiche le journal de réception : chaque message reçu, son origine et ce qu'on en a fait (prospect créé, alerte ignorée, quota atteint...).

## Lire les coordonnées d'un e-mail

1. Des règles repèrent le téléphone (06 12 34 56 78, +33 6 12 34 56 78, 06.12.34.56.78...) et l'e-mail du contact dans le texte, en écartant les adresses du portail, des expéditeurs automatiques et de l'agence elle-même.
2. L'IA (voir EXTRACTION_MODEL) lit le message pour le reste : nom, budget, secteur, type de bien, échéance, financement. Ce qu'elle annonce comme téléphone ou e-mail n'est gardé que s'il figure bien dans le message.
3. Si l'IA est absente ou en panne, le prospect est tout de même créé avec les coordonnées trouvées par les règles et le texte du message en note.
4. Quand plusieurs numéros ou adresses sont possibles, Zelyro n'en choisit pas : mieux vaut un champ vide qu'un mauvais numéro.

Mesurer la fiabilité sur des cas (même format que le dossier de test de Hugo) :

    python3 evaluer_extraction.py cases.json --sans-ia                 # règles seules, gratuit
    ANTHROPIC_API_KEY=... python3 evaluer_extraction.py cases.json 3   # règles + IA, 3 passages
    ANTHROPIC_API_KEY=... EXTRACTION_MODEL=claude-haiku-5-5 python3 evaluer_extraction.py cases.json

Pour changer de modèle en production, définir EXTRACTION_MODEL chez l'hébergeur (par défaut : claude-haiku-4-5-20251001). Comparer d'abord sur les cas.

## API de réception (pour un partenaire)

Base : https://saas-immobilier-921a.onrender.com

Chaque agence crée ses clés dans Compte, « Connexion par API » (jusqu'à 5). Une clé commence par zk_, n'est montrée qu'une fois, et ne permet que d'envoyer des prospects à cette agence. Elle se passe dans l'en-tête Authorization: Bearer zk_... (ou X-API-Key).

Tester la clé :

    curl https://saas-immobilier-921a.onrender.com/api/v1/inbound/ping -H "Authorization: Bearer zk_..."
    -> {"ok": true, "agency": "Nom de l'agence"}

Envoyer un prospect :

    curl -X POST https://saas-immobilier-921a.onrender.com/api/v1/inbound/leads \
      -H "Authorization: Bearer zk_..." -H "Content-Type: application/json" \
      -d '{"external_id": "ubi-1001", "source": "seloger", "name": "Julien Petit",
           "phone": "+33 6 11 22 33 44", "email": "julien.petit@example.com",
           "message": "Visite possible samedi ?", "listing_title": "T3 lumineux",
           "listing_ref": "A123", "transaction": "achat", "budget": 310000,
           "location": "Senlis", "property_type": "Appartement", "surface_min": 60}'
    -> 201 {"status": "created", "id": 42}

Champs : phone ou email obligatoire (au moins un des deux) ; name ; message ; source (seloger, leboncoin, ou un libellé libre) ; listing_title ; listing_ref ; transaction (achat ou location) ; budget (entier, euros) ; location ; property_type (Appartement, Maison, Villa, Studio, Penthouse, Terrain, Local commercial, Bureau) ; surface_min ; completion_email (true par défaut : pour une source seloger ou leboncoin avec e-mail, Zelyro écrit au prospect pour qu'il précise sa recherche) ; external_id (identifiant côté partenaire : renvoyer le même prospect ne le crée qu'une fois, la réponse est alors 200 avec status duplicate).

Réponses : 201 créé ; 200 doublon ; 400 données invalides (le message dit lesquelles) ; 401 clé absente, invalide ou supprimée, ou compte suspendu ; 403 quota de prospects du forfait atteint ; 429 trop de requêtes (2 000 par heure et par clé).

Les prospects reçus par API portent la source « API partenaire » (ou SeLoger / LeBonCoin si le partenaire l'indique) et déclenchent les mêmes alertes de rapprochement que les autres.
