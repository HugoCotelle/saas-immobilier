/**
 * INTEGRATION ARCHITECTURE - Multi-Channel Lead Ingestion
 * 
 * Problème: Leads arrivent sur Leboncoin, Seloger, Bien'ici, etc.
 * Agent ne doit PAS ressaisir manuellement.
 * 
 * Solution: Connecteurs automatiques qui pushent les leads directement au SaaS
 * 
 * Canaux supportés:
 * 1. Leboncoin (API officielle)
 * 2. Seloger (API officielle)  
 * 3. Bien'ici (API)
 * 4. Webhooks génériques (pour autres portails)
 * 5. Email parsing (secours)
 * 6. Import CSV/Excel (fallback)
 */

// ============================================================================
// ARCHITECTURE GÉNÉRALE
// ============================================================================

/*
                    PORTAILS IMMOBILIERS
                    ↓ ↓ ↓ ↓ ↓ (Leurs API)
    ┌───────────────────────────────────────────────┐
    │     SAAS INTEGRATION LAYER                    │
    ├───────────────────────────────────────────────┤
    │                                               │
    │  IntegrationManager (Orchestrateur)          │
    │  ├─ LeboncoinConnector                       │
    │  ├─ SelogerConnector                         │
    │  ├─ BienIciConnector                         │
    │  ├─ GenericWebhookReceiver                   │
    │  ├─ EmailParser                              │
    │  └─ CSVImporter                              │
    │                                               │
    │  LeadNormalizer (Mapping)                     │
    │  ├─ ExtractCriteria()                        │
    │  ├─ DetectPropertyType()                     │
    │  ├─ ParseBudget()                            │
    │  └─ MapToSaasModel()                         │
    │                                               │
    │  DuplicateDetector                            │
    │  ├─ CheckEmailDuplicate()                    │
    │  ├─ CheckPhoneDuplicate()                    │
    │  └─ FuzzyMatch()                             │
    │                                               │
    └───────────────────────────────────────────────┘
                    ↓
    ┌───────────────────────────────────────────────┐
    │     CORE SAAS                                 │
    ├───────────────────────────────────────────────┤
    │  LeadService.createLead()                     │
    │  ↓ Trigger MatchingService                    │
    │  ↓ Agent reçoit notification                  │
    └───────────────────────────────────────────────┘
*/

// ============================================================================
// FLOW: Quand un lead arrive de Leboncoin
// ============================================================================

/*
1. Leboncoin API webhook → POST /api/v1/integrations/leboncoin
2. LeboncoinConnector.parseWebhook(data)
   ├─ Extraire les infos (nom, email, budget, localisation, etc.)
   └─ Retourner format normalisé
3. LeadNormalizer.normalize(data)
   ├─ Détecter le type de bien (T2, maison, etc.) depuis la description
   ├─ Parser le budget
   ├─ Extraire les villes
   ├─ Récupérer les critères (meublé, parking, etc.)
   └─ Retourner modèle SaaS standard
4. DuplicateDetector.checkDuplicate()
   ├─ Email existe déjà?
   ├─ Téléphone existe déjà?
   └─ Fuzzy match sur le nom + email?
5. LeadService.createLead()
   ├─ Créer lead en BD
   ├─ Marquer source: "leboncoin"
   ├─ Marquer source_metadata avec ID externe
   └─ Déclencher matching automatiquement
6. Notifier l'agent → "📩 Nouveau lead Leboncoin - 3 biens matchés"
7. Agent ne refait PAS le travail manuellement ✅
*/

// ============================================================================
// TYPES DE CONNECTEURS NECESSAIRES
// ============================================================================

interface ConnectorAdapter {
  // Identifier le connecteur
  name: string;
  source: "leboncoin" | "seloger" | "bien_ici" | "other";
  
  // Parser un webhook/data entrant
  parseWebhook(data: any): Promise<NormalizedLead>;
  
  // Parser un message email (fallback)
  parseEmail(email: EmailMessage): Promise<NormalizedLead>;
  
  // Récupérer les leads en batch (sync)
  fetchLeads(agencyId: number): Promise<NormalizedLead[]>;
  
  // Vérifier la connexion
  validateConnection(): Promise<boolean>;
}

interface NormalizedLead {
  // Identifiant externe (pour éviter les doublons)
  externalId: string;
  source: string;
  sourceMetadata: {
    url?: string;
    originalData?: any;
    timestamp: Date;
  };
  
  // Infos prospect
  firstName: string;
  lastName: string;
  email?: string;
  phone?: string;
  
  // Critères de recherche (détectés automatiquement)
  transactionType: "sale" | "rent";
  propertyType: string;
  
  // Budget (parsé depuis texte)
  budgetMin?: number;
  budgetMax: number;
  
  // Surface (si disponible)
  surfaceMin?: number;
  
  // Villes recherchées
  cities: {
    name: string;
    postalCode?: string;
    departmentCode?: string;
  }[];
  
  // Critères détectés (parking, meublé, etc.)
  preferences: Array<{
    criteriaKey: string;
    value: boolean;
    importance: "mandatory" | "important" | "preferred";
  }>;
  
  // Confiance du parsing (0-100)
  confidence: number;
  
  // Notes d'extraction
  extractedNotes: string;
}

// ============================================================================
// 1. LEBONCOIN CONNECTOR
// ============================================================================

interface LeboncoinWebhookData {
  id: string;
  ad_type: "offer" | "request";  // "request" = lead
  
  // Infos prospect
  person: {
    name: string;
    email: string;
    phone: string;
  };
  
  // Description de la recherche
  description: string;
  
  // Propriétés de l'annonce
  ad: {
    category_name: string;  // "Locations" ou "Ventes"
    subject: string;         // ex: "Cherche T3 à Marseille"
    location: {
      city: string;
      postal_code: string;
      region_code: string;
    };
    price: {
      currency: string;
      amount: number;
    };
    parameters: Array<{
      key: string;
      value: string | number;
    }>;
  };
  
  created_at: string;
}

/*
Example:
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
      { "key": "furnished", "value": "true" }
    ]
  },
  "created_at": "2025-02-01T10:30:00Z"
}
*/

class LeboncoinConnector implements ConnectorAdapter {
  name = "Leboncoin";
  source = "leboncoin";
  
  private apiKey: string;
  private agencyId: number;
  
  constructor(apiKey: string, agencyId: number) {
    this.apiKey = apiKey;
    this.agencyId = agencyId;
  }
  
  async parseWebhook(data: LeboncoinWebhookData): Promise<NormalizedLead> {
    // Créer le lead normalisé
    const normalized: NormalizedLead = {
      externalId: data.id,
      source: "leboncoin",
      sourceMetadata: {
        url: `https://leboncoin.fr/.../${data.id}`,
        originalData: data,
        timestamp: new Date(data.created_at),
      },
      
      firstName: data.person.name.split(" ")[0],
      lastName: data.person.name.split(" ").slice(1).join(" "),
      email: data.person.email,
      phone: data.person.phone,
      
      transactionType: data.ad.category_name === "Locations" ? "rent" : "sale",
      propertyType: this.mapPropertyType(data.ad.parameters),
      
      budgetMax: data.ad.price.amount,
      
      cities: [
        {
          name: data.ad.location.city,
          postalCode: data.ad.location.postal_code,
          departmentCode: data.ad.location.region_code,
        },
      ],
      
      preferences: this.extractPreferences(data),
      
      confidence: 85, // Leboncoin a bonne qualité de data
      extractedNotes: `Importé depuis Leboncoin. Description: ${data.description}`,
    };
    
    return normalized;
  }
  
  private mapPropertyType(parameters: Array<{ key: string; value: any }>): string {
    const typeParam = parameters.find((p) => p.key === "type");
    
    const mapping: Record<string, string> = {
      "1_room": "studio",
      "2_rooms": "apartment",
      "3_rooms": "apartment",
      "4_rooms": "apartment",
      "5_rooms": "apartment",
      "house": "house",
      "villa": "villa",
    };
    
    return mapping[typeParam?.value as string] || "apartment";
  }
  
  private extractPreferences(
    data: LeboncoinWebhookData
  ): NormalizedLead["preferences"] {
    const prefs: NormalizedLead["preferences"] = [];
    
    const furnished = data.ad.parameters.find((p) => p.key === "furnished");
    if (furnished?.value === "true") {
      prefs.push({
        criteriaKey: "furnished",
        value: true,
        importance: "important",
      });
    }
    
    const parking = data.ad.parameters.find((p) => p.key === "parking");
    if (parking?.value === "true") {
      prefs.push({
        criteriaKey: "parking",
        value: true,
        importance: "preferred",
      });
    }
    
    // Analyser la description pour détecter d'autres critères
    const desc = data.description.toLowerCase();
    
    if (desc.includes("balcon")) {
      prefs.push({
        criteriaKey: "balcony",
        value: true,
        importance: "preferred",
      });
    }
    
    if (desc.includes("ascenseur")) {
      prefs.push({
        criteriaKey: "elevator",
        value: true,
        importance: "preferred",
      });
    }
    
    return prefs;
  }
  
  async validateConnection(): Promise<boolean> {
    // Test API key avec Leboncoin
    try {
      const response = await fetch("https://api.leboncoin.fr/v1/user/profile", {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      });
      return response.ok;
    } catch {
      return false;
    }
  }
  
  async fetchLeads(agencyId: number): Promise<NormalizedLead[]> {
    // Récupérer tous les leads reçus dans les 24h
    const response = await fetch(
      "https://api.leboncoin.fr/v1/requests?limit=100&created_after=24h",
      {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      }
    );
    
    const data = await response.json();
    
    return Promise.all(
      data.results.map((item: LeboncoinWebhookData) =>
        this.parseWebhook(item)
      )
    );
  }
  
  async parseEmail(email: EmailMessage): Promise<NormalizedLead> {
    // Fallback: parser un email reçu de Leboncoin
    throw new Error("Not implemented yet");
  }
}

// ============================================================================
// 2. SELOGER CONNECTOR
// ============================================================================

interface SelogerWebhookData {
  id: string;
  type: "search_request"; // Demandes de leads
  
  user: {
    firstName: string;
    lastName: string;
    email: string;
    phone: string;
  };
  
  search: {
    transactionType: "rent" | "sale";
    propertyTypes: string[];
    
    location: {
      cities: Array<{
        name: string;
        postalCode: string;
        departmentCode: string;
      }>;
    };
    
    budget: {
      min?: number;
      max: number;
    };
    
    surface?: {
      min?: number;
      max?: number;
    };
    
    rooms?: {
      min?: number;
      max?: number;
    };
    
    criteria: {
      furnished?: boolean;
      parking?: boolean;
      elevator?: boolean;
      balcony?: boolean;
    };
  };
  
  description: string;
  createdAt: string;
}

class SelogerConnector implements ConnectorAdapter {
  name = "Seloger";
  source = "seloger";
  
  private apiKey: string;
  private agencyId: number;
  
  constructor(apiKey: string, agencyId: number) {
    this.apiKey = apiKey;
    this.agencyId = agencyId;
  }
  
  async parseWebhook(data: SelogerWebhookData): Promise<NormalizedLead> {
    const preferences: NormalizedLead["preferences"] = [];
    
    if (data.search.criteria.furnished) {
      preferences.push({
        criteriaKey: "furnished",
        value: true,
        importance: "important",
      });
    }
    
    if (data.search.criteria.parking) {
      preferences.push({
        criteriaKey: "parking",
        value: true,
        importance: "important",
      });
    }
    
    if (data.search.criteria.elevator) {
      preferences.push({
        criteriaKey: "elevator",
        value: true,
        importance: "preferred",
      });
    }
    
    if (data.search.criteria.balcony) {
      preferences.push({
        criteriaKey: "balcony",
        value: true,
        importance: "preferred",
      });
    }
    
    const normalized: NormalizedLead = {
      externalId: data.id,
      source: "seloger",
      sourceMetadata: {
        url: `https://seloger.com/.../${data.id}`,
        originalData: data,
        timestamp: new Date(data.createdAt),
      },
      
      firstName: data.user.firstName,
      lastName: data.user.lastName,
      email: data.user.email,
      phone: data.user.phone,
      
      transactionType: data.search.transactionType,
      propertyType: data.search.propertyTypes[0] || "apartment",
      
      budgetMin: data.search.budget.min,
      budgetMax: data.search.budget.max,
      
      surfaceMin: data.search.surface?.min,
      
      cities: data.search.location.cities,
      preferences,
      
      confidence: 90, // Seloger a très bonne qualité de data
      extractedNotes: `Importé depuis Seloger. ${data.description}`,
    };
    
    return normalized;
  }
  
  async validateConnection(): Promise<boolean> {
    try {
      const response = await fetch("https://api.seloger.com/v1/me", {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      });
      return response.ok;
    } catch {
      return false;
    }
  }
  
  async fetchLeads(agencyId: number): Promise<NormalizedLead[]> {
    const response = await fetch(
      "https://api.seloger.com/v1/search-requests?created_after=24h",
      {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      }
    );
    
    const data = await response.json();
    
    return Promise.all(
      data.results.map((item: SelogerWebhookData) => this.parseWebhook(item))
    );
  }
  
  async parseEmail(email: EmailMessage): Promise<NormalizedLead> {
    throw new Error("Not implemented yet");
  }
}

// ============================================================================
// 3. BIEN'ICI CONNECTOR
// ============================================================================

class BienIciConnector implements ConnectorAdapter {
  name = "Bien'ici";
  source = "bien_ici";
  
  private apiKey: string;
  private agencyId: number;
  
  constructor(apiKey: string, agencyId: number) {
    this.apiKey = apiKey;
    this.agencyId = agencyId;
  }
  
  async parseWebhook(data: any): Promise<NormalizedLead> {
    // À implémenter selon API Bien'ici
    throw new Error("Not implemented yet");
  }
  
  async validateConnection(): Promise<boolean> {
    try {
      const response = await fetch("https://api.bienici.com/v1/profile", {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      });
      return response.ok;
    } catch {
      return false;
    }
  }
  
  async fetchLeads(agencyId: number): Promise<NormalizedLead[]> {
    throw new Error("Not implemented yet");
  }
  
  async parseEmail(email: EmailMessage): Promise<NormalizedLead> {
    throw new Error("Not implemented yet");
  }
}

// ============================================================================
// 4. GENERIC WEBHOOK RECEIVER
// ============================================================================

/*
Pour les portails qui n'ont pas de connecteur dédié,
on peut recevoir des webhooks génériques en JSON
*/

interface GenericWebhookPayload {
  lead: {
    firstName: string;
    lastName: string;
    email: string;
    phone?: string;
    message?: string;
  };
  property: {
    type: string;
    city: string;
    postalCode?: string;
    minBudget?: number;
    maxBudget: number;
    minSurface?: number;
  };
  source: string;
  sourceId: string;
  timestamp: string;
}

class GenericWebhookReceiver implements ConnectorAdapter {
  name = "Generic Webhook";
  source = "other";
  
  async parseWebhook(data: GenericWebhookPayload): Promise<NormalizedLead> {
    const normalized: NormalizedLead = {
      externalId: data.sourceId,
      source: data.source,
      sourceMetadata: {
        originalData: data,
        timestamp: new Date(data.timestamp),
      },
      
      firstName: data.lead.firstName,
      lastName: data.lead.lastName,
      email: data.lead.email,
      phone: data.lead.phone,
      
      transactionType: "rent", // À détecter
      propertyType: data.property.type,
      
      budgetMin: data.property.minBudget,
      budgetMax: data.property.maxBudget,
      
      surfaceMin: data.property.minSurface,
      
      cities: [
        {
          name: data.property.city,
          postalCode: data.property.postalCode,
        },
      ],
      
      preferences: [],
      
      confidence: 70, // Moins de données = moins de confiance
      extractedNotes: data.lead.message || "",
    };
    
    return normalized;
  }
  
  async validateConnection(): Promise<boolean> {
    return true; // Generic receiver ne se valide pas
  }
  
  async fetchLeads(agencyId: number): Promise<NormalizedLead[]> {
    return []; // Generic receiver ne fait que du webhook
  }
  
  async parseEmail(email: EmailMessage): Promise<NormalizedLead> {
    throw new Error("Not implemented yet");
  }
}

// ============================================================================
// 5. LEAD NORMALIZER (Mise en forme standard)
// ============================================================================

class LeadNormalizer {
  /**
   * Parser la description texte pour extraire les critères
   */
  static extractCriteria(text: string): Array<{
    criteriaKey: string;
    value: boolean;
  }> {
    const criteria: Array<{ criteriaKey: string; value: boolean }> = [];
    
    const text_lower = text.toLowerCase();
    
    const keywords: Record<string, string> = {
      parking: "parking|garage|place|stationnement",
      balcony: "balcon|terrasse",
      elevator: "ascenseur|étage",
      garden: "jardin|extérieur",
      furnished: "meublé|équipé",
      cellar: "cave|sous-sol",
    };
    
    for (const [key, pattern] of Object.entries(keywords)) {
      if (new RegExp(pattern).test(text_lower)) {
        criteria.push({ criteriaKey: key, value: true });
      }
    }
    
    return criteria;
  }
  
  /**
   * Parser le budget depuis texte
   */
  static parseBudget(text: string): { min?: number; max: number } {
    // Patterns: "1200€", "1200 euros", "jusqu'à 1200", "1000-1200", etc.
    const budgetRegex = /(\d+)\s*(?:€|euros?)?/gi;
    
    const matches = [...text.matchAll(budgetRegex)].map((m) =>
      parseInt(m[1])
    );
    
    if (matches.length === 0) {
      return { max: 0 };
    }
    
    if (matches.length === 1) {
      return { max: matches[0] };
    }
    
    return {
      min: Math.min(...matches),
      max: Math.max(...matches),
    };
  }
  
  /**
   * Détecter les villes depuis texte
   */
  static detectCities(text: string): string[] {
    // Utilisé une base de communes françaises
    // Simple regex pattern matching pour MVP
    const cityPatterns = [
      "marseille",
      "paris",
      "lyon",
      "aubagne",
      "boulogne",
    ];
    
    const found: string[] = [];
    
    for (const city of cityPatterns) {
      if (text.toLowerCase().includes(city)) {
        found.push(city);
      }
    }
    
    return found;
  }
}

// ============================================================================
// 6. DUPLICATE DETECTOR
// ============================================================================

class DuplicateDetector {
  private prisma: PrismaClient;
  
  constructor(prisma: PrismaClient) {
    this.prisma = prisma;
  }
  
  /**
   * Vérifier si un lead existe déjà (même email/téléphone)
   */
  async checkDuplicate(
    agencyId: number,
    lead: NormalizedLead
  ): Promise<boolean> {
    // Exact match sur email
    if (lead.email) {
      const existingEmail = await this.prisma.lead.findFirst({
        where: {
          agencyId,
          email: lead.email,
        },
      });
      
      if (existingEmail) {
        console.log(
          `[Duplicate] Lead with email ${lead.email} already exists`
        );
        return true;
      }
    }
    
    // Exact match sur téléphone
    if (lead.phone) {
      const existingPhone = await this.prisma.lead.findFirst({
        where: {
          agencyId,
          phone: lead.phone,
        },
      });
      
      if (existingPhone) {
        console.log(
          `[Duplicate] Lead with phone ${lead.phone} already exists`
        );
        return true;
      }
    }
    
    // Fuzzy match sur externalId (pour éviter les resends du webhook)
    const existingExternal = await this.prisma.lead.findFirst({
      where: {
        agencyId,
      },
      include: {
        // Chercher dans sourceMetadata
      },
    });
    
    // TODO: Implémenter fuzzy matching sur nom + email
    
    return false;
  }
}

// ============================================================================
// 7. INTEGRATION MANAGER (Orchestrateur)
// ============================================================================

class IntegrationManager {
  private prisma: PrismaClient;
  private leadService: LeadService;
  private matchingService: MatchingService;
  
  private connectors: Map<string, ConnectorAdapter>;
  private duplicateDetector: DuplicateDetector;
  
  constructor(
    prisma: PrismaClient,
    leadService: LeadService,
    matchingService: MatchingService
  ) {
    this.prisma = prisma;
    this.leadService = leadService;
    this.matchingService = matchingService;
    this.duplicateDetector = new DuplicateDetector(prisma);
    this.connectors = new Map();
  }
  
  /**
   * Enregistrer un connecteur pour une agence
   */
  registerConnector(
    agencyId: number,
    connector: ConnectorAdapter
  ): void {
    const key = `${agencyId}:${connector.source}`;
    this.connectors.set(key, connector);
  }
  
  /**
   * Webhook entrant d'un portail → Créer le lead
   */
  async receiveWebhook(
    agencyId: number,
    source: string,
    payload: any
  ): Promise<{
    success: boolean;
    leadId?: number;
    error?: string;
  }> {
    console.log(`[Integration] Receiving webhook from ${source} for agency ${agencyId}`);
    
    const key = `${agencyId}:${source}`;
    const connector = this.connectors.get(key);
    
    if (!connector) {
      return { success: false, error: `No connector configured for ${source}` };
    }
    
    try {
      // 1. Parser les données avec le connecteur
      const normalizedLead = await connector.parseWebhook(payload);
      
      console.log(
        `[Integration] Normalized lead: ${normalizedLead.firstName} ${normalizedLead.lastName}`
      );
      
      // 2. Vérifier les doublons
      const isDuplicate = await this.duplicateDetector.checkDuplicate(
        agencyId,
        normalizedLead
      );
      
      if (isDuplicate) {
        return {
          success: false,
          error: "Lead already exists in system",
        };
      }
      
      // 3. Créer le lead dans le SaaS
      const lead = await this.leadService.createLead({
        agencyId,
        firstName: normalizedLead.firstName,
        lastName: normalizedLead.lastName,
        email: normalizedLead.email,
        phone: normalizedLead.phone,
        source: normalizedLead.source,
        transactionType: normalizedLead.transactionType as "sale" | "rent",
        propertyType: normalizedLead.propertyType,
        budgetMin: normalizedLead.budgetMin,
        budgetMax: normalizedLead.budgetMax,
        surfaceMin: normalizedLead.surfaceMin,
        cities: normalizedLead.cities.map((c) => {
          // TODO: Récupérer city_id depuis le nom
          return 1; // Placeholder
        }),
        preferences: normalizedLead.preferences,
        notes: normalizedLead.extractedNotes,
      });
      
      console.log(
        `[Integration] Lead created: #${lead.id} with confidence ${normalizedLead.confidence}%`
      );
      
      // 4. Storer les metadata du connecteur
      await this.prisma.lead.update({
        where: { id: lead.id },
        data: {
          sourceMetadata: {
            ...normalizedLead.sourceMetadata,
            confidence: normalizedLead.confidence,
          } as any,
        },
      });
      
      return { success: true, leadId: lead.id };
    } catch (error) {
      console.error(`[Integration Error]`, error);
      return { success: false, error: String(error) };
    }
  }
  
  /**
   * Sync manual: Agent peut forcer la sync depuis un portail
   */
  async syncFromConnector(agencyId: number, source: string): Promise<{
    imported: number;
    duplicates: number;
    errors: number;
  }> {
    const key = `${agencyId}:${source}`;
    const connector = this.connectors.get(key);
    
    if (!connector) {
      throw new Error(`No connector configured for ${source}`);
    }
    
    const leads = await connector.fetchLeads(agencyId);
    
    let imported = 0;
    let duplicates = 0;
    let errors = 0;
    
    for (const lead of leads) {
      const result = await this.receiveWebhook(agencyId, source, lead);
      
      if (result.success) {
        imported++;
      } else if (result.error?.includes("already exists")) {
        duplicates++;
      } else {
        errors++;
      }
    }
    
    return { imported, duplicates, errors };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  IntegrationManager,
  LeboncoinConnector,
  SelogerConnector,
  BienIciConnector,
  GenericWebhookReceiver,
  LeadNormalizer,
  DuplicateDetector,
  ConnectorAdapter,
  NormalizedLead,
};
