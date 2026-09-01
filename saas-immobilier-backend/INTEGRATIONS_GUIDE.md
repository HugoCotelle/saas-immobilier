# 🔗 INTÉGRATIONS MULTI-CANAUX - Guide Complet

**Objectif**: Les leads arrivent directement des portails immobiliers (Leboncoin, Seloger, Bien'ici) vers le SaaS WITHOUT agent double-input.

---

## 📋 Table des matières

1. Architecture générale
2. Configuration par portail
3. Webhooks
4. API d'intégration
5. Gestion des doublons
6. Troubleshooting

---

## 🏗️ Architecture générale

### Flux: Lead Leboncoin → SaaS

```
1. Lead fait une demande sur Leboncoin
   ↓
2. Webhook Leboncoin envoie POST vers notre serveur
   POST /api/v1/integrations/webhooks/leboncoin
   ↓
3. LeboncoinConnector parse les données
   - Extraire nom, email, budget, localisation
   - Détecter type de bien, critères
   ↓
4. LeadNormalizer convertit en modèle SaaS
   - Budget: "1200€" → { budgetMax: 1200 }
   - Ville: "Marseille" → rechercher city_id
   - Critères: "parking" → { parking: true, importance: important }
   ↓
5. DuplicateDetector vérifie si lead existe
   - Email en doublon?
   - Téléphone en doublon?
   ↓
6. LeadService.createLead()
   - Créer lead en BD
   - Marquer source: "leboncoin"
   - Déclencher matching automatiquement
   ↓
7. Agent reçoit notification
   "🔥 Nouveau lead Leboncoin - Thomas Martin
    Recherche: T3 Marseille 800-1200€
    ✅ 3 biens matchés"
   ↓
8. Agent clique → Voir les biens
   (Pas besoin de ressaisir le lead!)
```

### Composants clés

```
IntegrationManager
├─ LeboncoinConnector
├─ SelogerConnector
├─ BienIciConnector
├─ GenericWebhookReceiver
└─ LeadNormalizer + DuplicateDetector
```

---

## 🔧 Configuration par portail

### 1. LEBONCOIN

#### Prerequis

- Compte professionnel Leboncoin
- API Developer Account
- API Key

#### Étapes de configuration

**Étape 1: Créer une application Leboncoin**

1. Aller sur https://developers.leboncoin.fr/
2. Créer une app:
   - Nom: "MonAgence SaaS"
   - Callback URL: `https://tondomaine.com/api/v1/integrations/webhooks/leboncoin?agency_id=1`

**Étape 2: Activer les webhooks**

1. Dans Leboncoin Dev Dashboard → Settings
2. Enable webhook: "search_requests" (demandes de leads)
3. Webhook URL: `https://tondomaine.com/api/v1/integrations/webhooks/leboncoin?agency_id=1`
4. Copier le `Webhook Secret`

**Étape 3: Configurer dans le SaaS**

```bash
# Appel API pour enregistrer l'intégration
curl -X POST https://tondomaine.com/api/v1/integrations/configure/leboncoin \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "your_leboncoin_api_key",
    "webhookSecret": "your_webhook_secret"
  }'

# Response:
{
  "success": true,
  "message": "Leboncoin configured successfully"
}
```

**Étape 4: Vérifier la connexion**

```bash
curl -X GET https://tondomaine.com/api/v1/integrations/status \
  -H "Authorization: Bearer <TOKEN>"

# Response:
{
  "integrations": [
    {
      "source": "leboncoin",
      "status": "connected",
      "lastCheckAt": "2025-02-01T10:30:00Z"
    }
  ],
  "totalConfigured": 1,
  "totalConnected": 1
}
```

#### Données reçues

Exemple de webhook reçu:

```json
{
  "id": "leboncoin_123456",
  "ad_type": "request",
  "person": {
    "name": "Thomas Martin",
    "email": "thomas@email.com",
    "phone": "0612345678"
  },
  "description": "Cherche un bel appartement T3 avec parking, idéalement meublé. Budget 1200€ max",
  "ad": {
    "category_name": "Locations",
    "subject": "T3 Marseille avec parking",
    "location": {
      "city": "Marseille",
      "postal_code": "13000",
      "region_code": "PACA"
    },
    "price": {
      "currency": "EUR",
      "amount": 1200
    },
    "parameters": [
      { "key": "type", "value": "3_rooms" },
      { "key": "furnished", "value": "true" },
      { "key": "parking", "value": "true" }
    ]
  },
  "created_at": "2025-02-01T10:30:00Z"
}
```

---

### 2. SELOGER

#### Prerequis

- Compte Pro Seloger
- Seloger API Access

#### Étapes de configuration

**Étape 1: Obtenir les accès**

1. Aller sur https://www.seloger.com/pro
2. Demander accès API
3. Recevoir API Key

**Étape 2: Configurer webhook**

```bash
curl -X POST https://tondomaine.com/api/v1/integrations/configure/seloger \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "your_seloger_api_key"
  }'
```

**Étape 3: Enregistrer le webhook dans Seloger**

```bash
# L'API du SaaS va configurer le webhook Seloger automatiquement
# ou manuellement:

curl -X POST https://api.seloger.com/v1/webhooks \
  -H "Authorization: Bearer your_seloger_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tondomaine.com/api/v1/integrations/webhooks/seloger?agency_id=1",
    "events": ["search_request"]
  }'
```

#### Données reçues

```json
{
  "id": "seloger_789",
  "type": "search_request",
  "user": {
    "firstName": "Sophie",
    "lastName": "Bernard",
    "email": "sophie@email.com",
    "phone": "0687654321"
  },
  "search": {
    "transactionType": "rent",
    "propertyTypes": ["apartment"],
    "location": {
      "cities": [
        {
          "name": "Paris",
          "postalCode": "75000",
          "departmentCode": "75"
        }
      ]
    },
    "budget": {
      "min": 1200,
      "max": 1800
    },
    "surface": {
      "min": 60
    },
    "rooms": {
      "min": 2
    },
    "criteria": {
      "furnished": false,
      "parking": true,
      "elevator": true
    }
  },
  "description": "Cherche un T3 bien équipé à Paris",
  "createdAt": "2025-02-01T11:00:00Z"
}
```

---

### 3. BIEN'ICI

#### Prerequis

- Compte Pro Bien'ici
- Bien'ici API credentials

#### Configuration

```bash
curl -X POST https://tondomaine.com/api/v1/integrations/configure/bien_ici \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "your_bienici_api_key"
  }'
```

---

### 4. PORTAIL GÉNÉRIQUE (Custom)

Pour un portail qui n'a pas de connecteur dédié, utiliser le webhook générique.

**Format JSON attendu:**

```json
{
  "lead": {
    "firstName": "Pierre",
    "lastName": "Dubois",
    "email": "pierre@email.com",
    "phone": "0612121212",
    "message": "Cherche un petit studio"
  },
  "property": {
    "type": "apartment",
    "city": "Marseille",
    "postalCode": "13000",
    "minBudget": 800,
    "maxBudget": 1200,
    "minSurface": 40
  },
  "source": "mon_portail",
  "sourceId": "monportail_456",
  "timestamp": "2025-02-01T12:00:00Z"
}
```

**Envoyer vers:**

```bash
POST https://tondomaine.com/api/v1/integrations/webhooks/generic?agency_id=1&source=mon_portail
Content-Type: application/json

{...payload...}
```

---

## 🔔 Webhooks - Configuration côté serveur

### Réception des webhooks

Les webhooks arrivent à:

```
POST /api/v1/integrations/webhooks/{source}

Avec query params:
- agency_id: ID de l'agence
- source: leboncoin|seloger|bien_ici|other
```

### Sécurité des webhooks

Chaque portail envoie une signature HMAC pour vérifier l'authenticité:

```
Headers:
X-Signature: sha256=...

Verification:
signature = HMAC-SHA256(
  message=request_body,
  secret=portail_webhook_secret
)
```

### Retours HTTP attendus

```
200 OK - Lead traité avec succès
{
  "success": true,
  "leadId": 123,
  "message": "Lead imported successfully"
}

200 OK - Lead en doublon (on le log mais pas d'erreur)
{
  "success": true,
  "message": "Duplicate ignored"
}

400 Bad Request - Erreur de parsing
{
  "success": false,
  "error": "Invalid format"
}

401 Unauthorized - Signature invalide
{
  "success": false,
  "error": "Invalid signature"
}
```

---

## 🔌 API d'intégration

### 1. Configurer une intégration

```bash
POST /api/v1/integrations/configure/:source

Headers:
Authorization: Bearer <TOKEN>
Content-Type: application/json

Body:
{
  "apiKey": "xxx",
  "webhookSecret": "yyy"  # optionnel selon source
}

Response:
{
  "success": true,
  "message": "leboncoin configured successfully"
}
```

### 2. Voir le statut

```bash
GET /api/v1/integrations/status

Headers:
Authorization: Bearer <TOKEN>

Response:
{
  "integrations": [
    {
      "source": "leboncoin",
      "status": "connected",
      "lastCheckAt": "2025-02-01T10:30:00Z",
      "errorMessage": null
    },
    {
      "source": "seloger",
      "status": "connected",
      "lastCheckAt": "2025-02-01T10:00:00Z",
      "errorMessage": null
    }
  ],
  "totalConfigured": 2,
  "totalConnected": 2
}
```

### 3. Sync manuelle

```bash
POST /api/v1/integrations/sync/:source

Headers:
Authorization: Bearer <TOKEN>

Response:
{
  "success": true,
  "imported": 5,
  "duplicates": 2,
  "errors": 0,
  "message": "Synced 5 leads from leboncoin"
}
```

### 4. Déconnecter

```bash
DELETE /api/v1/integrations/:source

Headers:
Authorization: Bearer <TOKEN>

Response:
{
  "success": true,
  "message": "leboncoin disconnected"
}
```

---

## 🔍 Gestion des doublons

### Détection

Le système vérifie:

1. **Email exact** - Lead avec même email existe?
2. **Téléphone exact** - Lead avec même téléphone existe?
3. **Fuzzy match** - Même nom + email similaire? (Levenstein distance)
4. **External ID** - Même ID externe (ex: leboncoin_123) déjà importé?

### Comportement

- Si doublon détecté → Lead ignoré, retour 200 OK (pas d'erreur)
- Log enregistré dans `integration_logs`
- Pas de création en BD

### Exemples

```
Cas 1: thomas@email.com arrive de Leboncoin
→ thomas@email.com existe déjà dans la BD
→ Lead ignoré (il a peut-être changé de portail)

Cas 2: 0612345678 (téléphone) arrive de Seloger
→ Même numéro existe déjà pour un lead
→ Lead ignoré

Cas 3: leboncoin_123456 arrive 2 fois
→ Même ID externe reçu (webhook resend)
→ Lead ignoré
```

---

## 📊 Monitoring & Logging

### Voir les logs d'intégration

```bash
GET /api/v1/integrations/logs?source=leboncoin&status=success

Response:
{
  "logs": [
    {
      "source": "leboncoin",
      "sourceId": "leboncoin_123456",
      "status": "success",
      "leadId": 456,
      "createdAt": "2025-02-01T10:30:00Z"
    },
    {
      "source": "leboncoin",
      "sourceId": "leboncoin_789",
      "status": "duplicate",
      "leadId": null,
      "createdAt": "2025-02-01T10:31:00Z"
    }
  ],
  "total": 2
}
```

### Métriques

Dashboard pour voir:

- Nombre de leads importés par source (jour/semaine/mois)
- Taux de doublons
- Taux d'erreur
- Dernière sync réussie

---

## 🚨 Troubleshooting

### "Invalid API key"

```
Vérifier:
✓ API key correcte depuis le portail
✓ API key n'a pas expiré
✓ API key a les bonnes permissions
✓ Appel de validation connect ici: connector.validateConnection()
```

### "Webhook not received"

```
Vérifier:
✓ Webhook URL enregistrée dans le portail
✓ URL exacte: https://domain.com/api/v1/integrations/webhooks/leboncoin?agency_id=X
✓ Firewall bloque pas les webhooks
✓ Signature HMAC correcte
✓ Server logs pour erreurs
```

### "All leads marked as duplicate"

```
Possible causes:
✓ Fuzzy match trop strict
✓ Système de cache dupliquant leads
✓ Même test data renvoyée plusieurs fois

Solution:
→ Vérifier DuplicateDetector logic
→ Augmenter threshold fuzzy match
→ Vider les logs d'intégration
```

### "Lead créé mais sans matching"

```
Vérifier:
✓ Villes parsées correctement (existe en BD?)
✓ Budget parsé correctement
✓ Type de bien reconnu
✓ Matching engine pas d'erreur (voir logs)
```

---

## 📈 Bénéfices

### Avant (Manual entry)

```
Lead arrive sur Leboncoin
↓
Agent voit notification
↓
Agent ouvre Leboncoin
↓
Agent lit le message
↓
Agent ressaisit manuellement dans le SaaS
↓
Agent lance le matching
↓
Agentcontacte le prospect
TIME: ~10 minutes 😞
```

### Après (Intégrations)

```
Lead arrive sur Leboncoin
↓
Webhook webhook envoie automatiquement
↓
SaaS crée le lead + lance matching
↓
Agent reçoit notification avec biens matchés
↓
Agent contacte immédiatement
TIME: <30 secondes ✅
```

---

## ✅ Checklist d'implémentation

Pour chaque portail:

- [ ] Créer un ConnectorAdapter
- [ ] Implémenter parseWebhook()
- [ ] Implémenter fetchLeads()
- [ ] Tester avec données réelles
- [ ] Documenter format webhook
- [ ] Ajouter tests unitaires
- [ ] Configurer webhook côté portail
- [ ] Tester l'intégration end-to-end
- [ ] Monitoring en place

---

## 🔐 Sécurité

### API Key Storage

```typescript
// JAMAIS en clair!
// Toujours chiffrer avant stocker en BD:

apiKey = encrypt(apiKey)
// Stocké en BD: U2FsdGVkX1...

// Au retrieval:
apiKey = decrypt(storedApiKey)
```

### Signature Verification

```typescript
// Toujours vérifier HMAC avant de traiter

function verifySignature(body, signature, secret) {
  const expected = HMAC_SHA256(body, secret)
  return constantTimeCompare(expected, signature)
}
```

### Rate Limiting

```
Limiter:
- Par agency_id
- Par source
- Par IP

Exemple:
- Max 100 webhooks/min par agency
- Max 10,000 par jour
```

---

## 📞 Support

Pour des questions ou issues:
1. Vérifier les logs d'intégration
2. Consulter le troubleshooting
3. Vérifier la doc du portail
4. Ouvrir une issue sur le repo

---

**Version**: 1.0.0  
**Last updated**: Février 2025  
**Status**: Production-ready
