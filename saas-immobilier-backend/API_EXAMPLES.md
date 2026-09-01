# Exemples API - SaaS Immobilier

Exemples cURL pour tester l'API du SaaS.

---

## 🔐 Authentication

### 1. Générer un JWT (depuis le code)

Pour les tests, utilise ce script:

```typescript
import { generateToken } from "./src/middleware/auth.middleware";

// Agent Jean Dupont - Marseille Immo
const token = generateToken(
  userId = 1,  // ID de l'utilisateur
  email = "jean.dupont@marseille-immo.fr",
  agencyId = 1,  // ID de l'agence
  role = "agent"
);

console.log(token);
```

### 2. Utiliser le token

Remplacer `<TOKEN>` dans les exemples ci-dessous.

---

## 📋 Leads

### Créer un lead

```bash
curl -X POST http://localhost:3000/api/v1/leads \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "firstName": "Pierre",
    "lastName": "Dubois",
    "email": "pierre@email.com",
    "phone": "06 12 34 56 78",
    "source": "website",
    "transactionType": "rent",
    "propertyType": "apartment",
    "budgetMin": 900,
    "budgetMax": 1300,
    "surfaceMin": 55,
    "bedroomsMin": 2,
    "cities": [1, 2],
    "preferences": [
      {
        "criteriaKey": "parking",
        "value": "true",
        "importance": "important"
      },
      {
        "criteriaKey": "elevator",
        "value": "true",
        "importance": "preferred"
      }
    ]
  }'
```

**Response (201 Created):**
```json
{
  "success": true,
  "lead": {
    "id": 3,
    "agencyId": 1,
    "firstName": "Pierre",
    "lastName": "Dubois",
    "email": "pierre@email.com",
    "phone": "06 12 34 56 78",
    "source": "website",
    "transactionType": "rent",
    "propertyType": "apartment",
    "budgetMin": 900,
    "budgetMax": 1300,
    "surfaceMin": 55,
    "bedroomsMin": 2,
    "status": "new",
    "priority": "normal",
    "createdAt": "2025-02-01T10:30:00Z",
    "updatedAt": "2025-02-01T10:30:00Z",
    "leadCities": [
      { "id": 1, "leadId": 3, "cityId": 1 },
      { "id": 2, "leadId": 3, "cityId": 2 }
    ],
    "preferences": [
      { "id": 1, "leadId": 3, "criteriaKey": "parking", "value": "true", "importance": "important" },
      { "id": 2, "leadId": 3, "criteriaKey": "elevator", "value": "true", "importance": "preferred" }
    ]
  }
}
```

---

### Récupérer tous les leads

```bash
curl -X GET "http://localhost:3000/api/v1/leads?status=new&take=10" \
  -H "Authorization: Bearer <TOKEN>"
```

**Response (200 OK):**
```json
{
  "leads": [
    {
      "id": 1,
      "firstName": "Thomas",
      "lastName": "Martin",
      "status": "new",
      "priority": "hot",
      "budgetMax": 1200,
      "leadCities": [...],
      "preferences": [...]
    }
  ],
  "counts": {
    "new": 2,
    "contacted": 0,
    "qualified": 0,
    "properties_sent": 0,
    "visit_scheduled": 0,
    "offer": 0,
    "won": 0,
    "lost": 0
  }
}
```

---

### Récupérer un lead avec ses matches

```bash
curl -X GET http://localhost:3000/api/v1/leads/1 \
  -H "Authorization: Bearer <TOKEN>"
```

**Response (200 OK):**
```json
{
  "lead": {
    "id": 1,
    "firstName": "Thomas",
    "lastName": "Martin",
    "email": "thomas.martin@email.com",
    "phone": "06 11 22 33 44",
    "status": "new",
    "priority": "hot",
    "budgetMin": 800,
    "budgetMax": 1200,
    "surfaceMin": 50,
    "bedroomsMin": 2,
    "leadCities": [
      { "id": 1, "leadId": 1, "cityId": 1 },
      { "id": 2, "leadId": 1, "cityId": 2 }
    ],
    "preferences": [
      { "criteriaKey": "parking", "value": "true", "importance": "important" },
      { "criteriaKey": "balcony", "value": "true", "importance": "preferred" }
    ]
  },
  "matches": [
    {
      "score": 94.5,
      "property": {
        "id": 1,
        "reference": "MAR-001",
        "title": "T3 Marseille 8e - Lumineux",
        "transactionType": "rent",
        "propertyType": "apartment",
        "price": 1150,
        "surface": 65,
        "bedrooms": 2,
        "hasParking": true,
        "hasBalcony": false
      },
      "matchDetails": {
        "leadId": 1,
        "propertyId": 1,
        "score": 94.5,
        "eligible": true,
        "criteria": {
          "city": { "matched": true, "score": 100, "weight": 25, "reason": "City in lead preferences" },
          "budget": { "matched": true, "score": 100, "weight": 25, "reason": "Price within budget" },
          "surface": { "matched": true, "score": 90, "weight": 15, "reason": "Surface exceeds minimum by >30%" },
          "bedrooms": { "matched": true, "score": 100, "weight": 15, "reason": "Exact bedroom match: 2" },
          "property_type": { "matched": true, "score": 100, "weight": 10, "reason": "Property type matches exactly" },
          "equipments": { "matched": true, "score": 60, "weight": 10, "reason": "Equipments scoring" }
        },
        "reasons": [
          "city_match",
          "budget_match",
          "surface_match",
          "bedrooms_match",
          "property_type_match",
          "parking_available"
        ],
        "warnings": [
          "balcony_missing"
        ]
      }
    },
    {
      "score": 89.2,
      "property": {
        "id": 2,
        "reference": "MAR-002",
        "title": "T4 Marseille 6e - Récent",
        "price": 1300,
        "surface": 85,
        "bedrooms": 3
      }
    }
  ]
}
```

---

### Mettre à jour le statut d'un lead

```bash
curl -X PUT http://localhost:3000/api/v1/leads/1/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "status": "contacted"
  }'
```

**Response (200 OK):**
```json
{
  "success": true,
  "lead": {
    "id": 1,
    "status": "contacted",
    "firstContactAt": "2025-02-01T10:35:00Z"
  }
}
```

---

### Assigner un lead à un agent

```bash
curl -X PUT http://localhost:3000/api/v1/leads/1/assign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "agentId": 2
  }'
```

---

### Ajouter une ville au lead

```bash
curl -X POST http://localhost:3000/api/v1/leads/1/cities \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "cityId": 3,
    "priority": "acceptable"
  }'
```

---

### Ajouter une préférence au lead

```bash
curl -X POST http://localhost:3000/api/v1/leads/1/preferences \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "criteriaKey": "furnished",
    "value": "false",
    "importance": "important"
  }'
```

---

### Enregistrer une activité

```bash
curl -X POST http://localhost:3000/api/v1/leads/1/activities \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "actionType": "call",
    "description": "Called prospect, very interested, wants visit next week"
  }'
```

---

### Dashboard avec tops matchs

```bash
curl -X GET http://localhost:3000/api/v1/leads/dashboard/overview \
  -H "Authorization: Bearer <TOKEN>"
```

**Response:**
```json
{
  "leads": [
    {
      "id": 1,
      "firstName": "Thomas",
      "status": "new",
      "topMatches": [
        { "score": 94.5, "property": { ... } },
        { "score": 89.2, "property": { ... } }
      ],
      "matchCount": 3
    }
  ],
  "stats": {
    "new": 2,
    "contacted": 1,
    "qualified": 0,
    "properties_sent": 0,
    "visit_scheduled": 0,
    "offer": 0,
    "won": 0,
    "lost": 0
  },
  "matchingStats": {
    "totalMatches": 7,
    "leadsWithMatches": 2,
    "avgMatchScore": 87.3,
    "matchingRate": 100
  }
}
```

---

## 🏠 Properties

### Créer un bien

```bash
curl -X POST http://localhost:3000/api/v1/properties \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "reference": "MAR-003",
    "title": "Studio Marseille Centre",
    "transactionType": "rent",
    "propertyType": "studio",
    "cityId": 1,
    "address": "99 Rue Paradis",
    "postalCode": "13006",
    "price": 650,
    "surface": 28,
    "rooms": 1,
    "bedrooms": 0,
    "bathrooms": 1,
    "floor": 2,
    "hasElevator": true,
    "hasParking": false,
    "isFurnished": true,
    "availabilityDate": "2025-03-01",
    "description": "Petit studio meublé idéal pour étudiant"
  }'
```

---

### Récupérer tous les biens

```bash
curl -X GET "http://localhost:3000/api/v1/properties?status=available&take=20" \
  -H "Authorization: Bearer <TOKEN>"
```

---

### Récupérer un bien avec ses leads correspondants

```bash
curl -X GET http://localhost:3000/api/v1/properties/1 \
  -H "Authorization: Bearer <TOKEN>"
```

**Response:**
```json
{
  "property": {
    "id": 1,
    "reference": "MAR-001",
    "title": "T3 Marseille 8e - Lumineux",
    "transactionType": "rent",
    "propertyType": "apartment",
    "price": 1150,
    "surface": 65,
    "bedrooms": 2,
    "hasParking": true,
    "hasBalcony": false
  },
  "matches": [
    {
      "score": 94.5,
      "lead": {
        "id": 1,
        "firstName": "Thomas",
        "lastName": "Martin",
        "email": "thomas@email.com"
      },
      "matchDetails": { ... }
    },
    {
      "score": 78.3,
      "lead": {
        "id": 3,
        "firstName": "Pierre",
        "lastName": "Dubois"
      }
    }
  ]
}
```

---

### Mettre à jour le statut d'un bien

```bash
curl -X PUT http://localhost:3000/api/v1/properties/1/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "status": "sold"
  }'
```

---

### Assigner un bien à un agent

```bash
curl -X PUT http://localhost:3000/api/v1/properties/1/assign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "agentId": 2
  }'
```

---

### Supprimer un bien

```bash
curl -X DELETE http://localhost:3000/api/v1/properties/1 \
  -H "Authorization: Bearer <TOKEN>"
```

---

### Dashboard des biens

```bash
curl -X GET http://localhost:3000/api/v1/properties/dashboard/overview \
  -H "Authorization: Bearer <TOKEN>"
```

---

## 📊 Scenarios de test complets

### Scenario 1: Nouveau lead arrive → Voir ses matchs

```bash
# 1. Créer un lead
LEAD_JSON=$(curl -X POST http://localhost:3000/api/v1/leads \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{...}')

LEAD_ID=$(echo $LEAD_JSON | jq '.lead.id')

# 2. Récupérer le lead avec matchs
curl -X GET http://localhost:3000/api/v1/leads/$LEAD_ID \
  -H "Authorization: Bearer <TOKEN>"

# 3. Voir le top match
# Résultat: 94.5% - T3 Marseille 8e
```

---

### Scenario 2: Nouveau bien arrive → ReMatcher avec leads existants

```bash
# 1. Créer un bien
PROP_JSON=$(curl -X POST http://localhost:3000/api/v1/properties \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{...}')

PROP_ID=$(echo $PROP_JSON | jq '.property.id')

# 2. Récupérer le bien avec leads correspondants
curl -X GET http://localhost:3000/api/v1/properties/$PROP_ID \
  -H "Authorization: Bearer <TOKEN>"

# 3. Voir les leads matchés
# Résultat: 7 leads correspondent, top: 92%
```

---

## ✅ Checklist de test

- [ ] Créer 3 leads
- [ ] Vérifier que les leads voient les biens matchés
- [ ] Créer 2 biens
- [ ] Vérifier que les biens voient les leads matchés
- [ ] Mettre à jour statut lead
- [ ] Assigner lead à agent
- [ ] Enregistrer activité
- [ ] Vérifier dashboard overview
- [ ] Vérifier les scores sont corrects (0-100)
- [ ] Vérifier les raisons du score sont explicites

---

**Besoin d'aide?** Voir `README.md` pour plus de détails.
