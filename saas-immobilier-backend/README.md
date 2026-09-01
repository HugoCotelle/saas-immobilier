# SaaS Immobilier - Backend API

**Plateforme de matching leads ↔ biens pour agences immobilières**

Une API universelle que n'importe quelle agence peut utiliser via web, API REST, ou intégrations tierces.

---

## 🚀 Quick Start

### 1. Installation

```bash
# Cloner et installer
git clone <repo>
cd saas-immobilier-backend
npm install

# Copier le fichier d'environnement
cp .env.example .env
```

### 2. Configuration de la base de données

```bash
# Créer la base PostgreSQL
createdb saas_immobilier

# Configurer DATABASE_URL dans .env
DATABASE_URL="postgresql://user:password@localhost:5432/saas_immobilier"

# Appliquer les migrations
npm run prisma:migrate
```

### 3. Démarrer le serveur

```bash
# Mode développement (avec hot-reload)
npm run dev

# Mode production
npm run build
npm start
```

Le serveur démarre sur `http://localhost:3000`

---

## 📚 Architecture

### Stack Technique

- **Runtime**: Node.js + TypeScript
- **Framework**: Express.js
- **Database**: PostgreSQL 14+
- **ORM**: Prisma
- **Auth**: JWT (jsonwebtoken)
- **Validation**: Zod (optionnel)

### Modules

```
src/
├── index.ts                 # Entry point
├── services/
│   ├── matching.engine.ts   # ⭐ Moteur de matching
│   ├── matching.service.ts  # Orchestration
│   ├── lead.service.ts      # Gestion des leads
│   └── property.service.ts  # Gestion des biens
├── routes/
│   ├── leads.routes.ts      # API Leads
│   └── properties.routes.ts # API Properties
├── middleware/
│   └── auth.middleware.ts   # JWT + Roles
├── types/                   # Types TypeScript
└── utils/                   # Utilitaires
```

---

## 🔐 Authentification

### Générer un JWT

```typescript
import { generateToken } from "@middleware/auth.middleware";

const token = generateToken(
  userId = 1,
  email = "agent@agency.com",
  agencyId = 1,
  role = "agent"
);
```

### Utiliser l'API

Ajouter le header:
```
Authorization: Bearer <token>
```

---

## 📖 API Endpoints

### Leads

#### Créer un lead
```bash
POST /api/v1/leads
Content-Type: application/json
Authorization: Bearer <token>

{
  "firstName": "Thomas",
  "lastName": "Martin",
  "email": "thomas@email.com",
  "phone": "06 XX XX XX XX",
  "source": "website",
  "transactionType": "rent",
  "propertyType": "apartment",
  "budgetMin": 800,
  "budgetMax": 1200,
  "surfaceMin": 50,
  "bedroomsMin": 2,
  "cities": [1, 2, 3],  // IDs des communes
  "preferences": [
    {
      "criteriaKey": "parking",
      "value": "true",
      "importance": "important"
    },
    {
      "criteriaKey": "balcony",
      "value": "true",
      "importance": "preferred"
    }
  ]
}
```

#### Récupérer les leads
```bash
GET /api/v1/leads?status=new&take=50
Authorization: Bearer <token>
```

#### Récupérer un lead avec ses matchs
```bash
GET /api/v1/leads/123
Authorization: Bearer <token>

Response:
{
  "lead": { ... },
  "matches": [
    {
      "score": 94.5,
      "property": { ... },
      "matchDetails": { ... }
    },
    ...
  ]
}
```

#### Mettre à jour le statut
```bash
PUT /api/v1/leads/123/status
Authorization: Bearer <token>

{
  "status": "contacted"
}
```

#### Assigner à un agent
```bash
PUT /api/v1/leads/123/assign
Authorization: Bearer <token>

{
  "agentId": 5
}
```

#### Ajouter une ville recherchée
```bash
POST /api/v1/leads/123/cities
Authorization: Bearer <token>

{
  "cityId": 5,
  "priority": "preferred"
}
```

#### Enregistrer une activité (call, email, etc.)
```bash
POST /api/v1/leads/123/activities
Authorization: Bearer <token>

{
  "actionType": "call",
  "description": "Called prospect, interested in visit"
}
```

#### Dashboard avec meilleurs matchs
```bash
GET /api/v1/leads/dashboard/overview
Authorization: Bearer <token>
```

---

### Properties

#### Créer un bien
```bash
POST /api/v1/properties
Content-Type: application/json
Authorization: Bearer <token>

{
  "reference": "MAR-001",
  "title": "T3 Marseille 8e",
  "transactionType": "rent",
  "propertyType": "apartment",
  "cityId": 1,
  "address": "123 Rue de la Canebière",
  "postalCode": "13008",
  "price": 1150,
  "surface": 65,
  "rooms": 3,
  "bedrooms": 2,
  "bathrooms": 1,
  "floor": 2,
  "hasElevator": true,
  "hasBalcony": false,
  "hasParking": true,
  "isFurnished": false,
  "availabilityDate": "2025-02-01",
  "description": "Bel appartement lumineux..."
}
```

#### Récupérer les biens
```bash
GET /api/v1/properties?status=available&transactionType=rent
Authorization: Bearer <token>
```

#### Récupérer un bien avec ses leads correspondants
```bash
GET /api/v1/properties/456
Authorization: Bearer <token>

Response:
{
  "property": { ... },
  "matches": [
    {
      "score": 94.5,
      "lead": { ... },
      "matchDetails": { ... }
    },
    ...
  ]
}
```

#### Mettre à jour le statut
```bash
PUT /api/v1/properties/456/status
Authorization: Bearer <token>

{
  "status": "sold"
}
```

#### Assigner à un agent
```bash
PUT /api/v1/properties/456/assign
Authorization: Bearer <token>

{
  "agentId": 5
}
```

---

## 🧠 Moteur de Matching

Le cœur du SaaS. Expliqué en détail dans `ARCHITECTURE_SAAS_IMMOBILIER.md`

### Flux

```
Lead arrive
    ↓
matchingEngine.calculateMatch(lead, property, agencyId, preferences)
    ↓
1. Validation multi-tenant
2. Filtres bloquants (type, ville, budget, etc.)
3. Scoring (6 critères pondérés)
4. Génération des raisons (explicabilité)
5. Retour du score 0-100
```

### Critères de scoring

- **Ville** (25%) - Lead.cities match Property.city?
- **Budget** (25%) - Property.price <= Lead.budgetMax?
- **Surface** (15%) - Property.surface >= Lead.surfaceMin?
- **Chambres** (15%) - Property.bedrooms >= Lead.bedroomsMin?
- **Type de bien** (10%) - Exact ou similaire?
- **Équipements** (10%) - Parking, balcon, etc.

### Exemple de résultat

```json
{
  "leadId": 123,
  "propertyId": 456,
  "agencyId": 1,
  "score": 94.5,
  "eligible": true,
  
  "criteria": {
    "city": {
      "matched": true,
      "score": 100,
      "weight": 25,
      "reason": "City in lead preferences"
    },
    "budget": {
      "matched": true,
      "score": 100,
      "weight": 25,
      "reason": "Price within budget"
    },
    ...
  },
  
  "reasons": [
    "city_match",
    "budget_match",
    "surface_match",
    "parking_available"
  ],
  
  "warnings": [
    "balcony_missing"
  ]
}
```

---

## 🗄️ Base de données

### Schéma

Voir `prisma/schema.prisma` pour le schéma complet.

**Tables principales:**
- `cities` - Communes françaises
- `agencies` - Agences immobilières
- `users` - Utilisateurs (admin, manager, agent)
- `properties` - Biens immobiliers
- `leads` - Prospects
- `lead_cities` - Villes recherchées par lead
- `lead_preferences` - Critères du lead
- `matches` - Résultats du matching (historique)
- `lead_activities` - Audit trail

### Migrations

```bash
# Créer une migration
npm run prisma:migrate

# Voir l'historique
npx prisma migrate status

# Rollback
npx prisma migrate resolve --rolled-back <migration_name>

# Studio (GUI)
npm run prisma:studio
```

---

## 🔐 Sécurité Multi-Tenant

**Règle fondamentale**: Aucun lead d'une agence ne doit voir les biens d'une autre agence.

### Implémentation

1. **Middleware d'authentification**
   ```typescript
   authenticateJWT // Vérifier le JWT
   enforceAgencyContext // Vérifier agency_id match
   ```

2. **Chaque requête filtrée**
   ```sql
   WHERE agency_id = authenticated_user.agency_id
   ```

3. **Validation multi-tenant dans le moteur**
   ```typescript
   if (lead.agencyId !== property.agencyId) {
     throw new Error("Multi-tenant violation");
   }
   ```

---

## 📊 Analytics

Voir les statistiques de matching d'une agence:

```bash
GET /api/v1/leads/dashboard/overview
Authorization: Bearer <token>

Response:
{
  "leads": [...],
  "stats": {
    "new": 5,
    "contacted": 12,
    "qualified": 8,
    ...
  },
  "matchingStats": {
    "totalMatches": 45,
    "leadsWithMatches": 12,
    "avgMatchScore": 82.5,
    "matchingRate": 67  // %
  }
}
```

---

## 🛠️ Développement

### Commandes

```bash
# Dev
npm run dev

# Build
npm run build

# Lint
npm run lint

# Type check
npm run type-check

# Tests
npm test
npm run test:watch

# Seed DB (futur)
npm run seed
```

### Ajouter une nouvelle route

1. Créer le service
2. Créer les routes dans `src/routes/`
3. Importer dans `src/index.ts`

Exemple:

```typescript
// src/routes/example.routes.ts
import { Router } from "express";
import { authenticateJWT } from "@middleware/auth.middleware";

const router = Router();

router.get("/", authenticateJWT, (req, res) => {
  res.json({ message: "Hello" });
});

export default router;
```

---

## 📝 Logging

Le serveur log automatiquement les erreurs:

```
[Matching] Lead #123 - Found 50 candidate properties
[Matching] Lead #123 - Got 3 eligible matches
[Error] Failed to create lead: Database error
```

---

## 🚀 Déploiement

### Heroku

```bash
git push heroku main
heroku run npm run prisma:migrate
```

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
CMD ["npm", "start"]
```

### Environment Variables (Production)

```
DATABASE_URL=postgresql://...
JWT_SECRET=<very-secure-key>
NODE_ENV=production
PORT=3000
```

---

## 📚 Documentation additionnelle

- `ARCHITECTURE_SAAS_IMMOBILIER.md` - Architecture complète + Moteur de matching
- `prisma/schema.prisma` - Schéma de base de données
- `src/services/matching.engine.ts` - Implémentation du moteur

---

## ✅ Checklist V1

- [x] Schéma Prisma complet
- [x] Moteur de matching (déterministe)
- [x] API REST (Leads + Properties)
- [x] Authentification JWT
- [x] Sécurité multi-tenant
- [ ] Tests unitaires
- [ ] Tests d'intégration
- [ ] Documentation Swagger/OpenAPI
- [ ] Seed données de test
- [ ] Frontend React (optionnel)

---

## 🐛 Troubleshooting

### Erreur: Database connection failed
```bash
# Vérifier DATABASE_URL
echo $DATABASE_URL

# Vérifier PostgreSQL
psql -U postgres -c "\l"
```

### Erreur: JWT expired
```bash
# Générer un nouveau token
```

### Erreur: Agency context mismatch
- Vérifier que le token JWT contient l'agencyId correct
- Vérifier que l'agencyId dans la requête match le token

---

## 📧 Support

Questions? Créer une issue sur le repo.

---

**Version**: 1.0.0  
**Status**: 🟢 Production Ready
