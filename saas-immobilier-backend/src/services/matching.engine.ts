/**
 * MATCHING ENGINE - Cœur du SaaS
 * 
 * Responsable de:
 * 1. Validation multi-tenant
 * 2. Filtres bloquants
 * 3. Calcul du score (0-100)
 * 4. Génération des raisons
 * 5. Classement des résultats
 */

import { Prisma, Lead, Property, City } from "@prisma/client";

// ============================================================================
// TYPES
// ============================================================================

export interface CriteriaScore {
  name: string;
  score: number; // 0-100
  weight: number; // En %
  matched: boolean;
  reason: string;
  warning?: string;
}

export interface MatchResult {
  leadId: number;
  propertyId: number;
  agencyId: number;
  score: number; // 0-100, ex: 94.5
  eligible: boolean;
  criteria: Record<string, CriteriaScore>;
  reasons: string[]; // Critères matchant
  warnings: string[]; // Critères manquants
  calculationTimeMs: number;
  timestamp: Date;
}

export interface MatchingConfig {
  weights: {
    city: number;
    budget: number;
    surface: number;
    bedrooms: number;
    propertyType: number;
    equipments: number;
  };
  blocking: {
    blockIfBudgetExceeded: boolean;
    blockIfCityMismatch: boolean;
    blockIfTypeMismatch: boolean;
  };
}

// ============================================================================
// DEFAULT CONFIG
// ============================================================================

const DEFAULT_CONFIG: MatchingConfig = {
  weights: {
    city: 25,
    budget: 25,
    surface: 15,
    bedrooms: 15,
    propertyType: 10,
    equipments: 10,
  },
  blocking: {
    blockIfBudgetExceeded: true,
    blockIfCityMismatch: true,
    blockIfTypeMismatch: true,
  },
};

// ============================================================================
// MATCHING ENGINE CLASS
// ============================================================================

export class MatchingEngine {
  private config: MatchingConfig;

  constructor(config: Partial<MatchingConfig> = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
    };
  }

  /**
   * ÉTAPE 1: Validation multi-tenant
   * Vérifier que lead et property appartiennent à la même agence
   */
  private validateMultiTenant(
    lead: Lead,
    property: Property,
    agencyId: number
  ): { valid: boolean; error?: string } {
    if (lead.agencyId !== agencyId) {
      return { valid: false, error: "Lead does not belong to this agency" };
    }

    if (property.agencyId !== agencyId) {
      return {
        valid: false,
        error: "Property does not belong to this agency",
      };
    }

    if (lead.agencyId !== property.agencyId) {
      return {
        valid: false,
        error: "Lead and property are not in the same agency",
      };
    }

    return { valid: true };
  }

  /**
   * ÉTAPE 2: Filtres bloquants - Transaction type
   */
  private scoreTransactionType(
    lead: Lead,
    property: Property
  ): {
    score: number;
    matched: boolean;
    reason: string;
    blocked: boolean;
  } {
    const matched =
      lead.transactionType.toLowerCase() ===
      property.transactionType.toLowerCase();

    return {
      score: matched ? 100 : 0,
      matched,
      reason: matched
        ? `${lead.transactionType} match`
        : `${lead.transactionType} vs ${property.transactionType}`,
      blocked: !matched && this.config.blocking.blockIfTypeMismatch,
    };
  }

  /**
   * ÉTAPE 3: Filtres bloquants - Type de bien
   */
  private scorePropertyType(
    lead: Lead,
    property: Property
  ): {
    score: number;
    matched: boolean;
    reason: string;
    blocked: boolean;
  } {
    const leadType = lead.propertyType.toLowerCase();
    const propType = property.propertyType.toLowerCase();

    // Exact match
    if (leadType === propType) {
      return {
        score: 100,
        matched: true,
        reason: "Property type matches exactly",
        blocked: false,
      };
    }

    // Similar types
    const similarTypes: Record<string, string[]> = {
      apartment: ["studio", "apartment"],
      studio: ["studio", "apartment"],
      house: ["house", "villa"],
      villa: ["house", "villa"],
      commercial: ["commercial", "office"],
      office: ["commercial", "office"],
    };

    const leadSimilar = similarTypes[leadType] || [];
    const isSimilar = leadSimilar.includes(propType);

    if (isSimilar) {
      return {
        score: 80,
        matched: true,
        reason: `${leadType} and ${propType} are similar`,
        blocked: false,
      };
    }

    return {
      score: 0,
      matched: false,
      reason: `${leadType} does not match ${propType}`,
      blocked: this.config.blocking.blockIfTypeMismatch,
    };
  }

  /**
   * ÉTAPE 4: Filtres bloquants - Ville
   */
  private scoreCity(
    leadCityIds: number[],
    property: Property
  ): {
    score: number;
    matched: boolean;
    reason: string;
    blocked: boolean;
  } {
    const matched = leadCityIds.includes(property.cityId);

    return {
      score: matched ? 100 : 0,
      matched,
      reason: matched ? "City matches lead preferences" : "City not in preferences",
      blocked: !matched && this.config.blocking.blockIfCityMismatch,
    };
  }

  /**
   * ÉTAPE 5: Filtres bloquants + Scoring - Budget
   */
  private scoreBudget(lead: Lead, property: Property): {
    score: number;
    matched: boolean;
    reason: string;
    blocked: boolean;
  } {
    const propPrice = property.price.toNumber();
    const budgetMax = lead.budgetMax.toNumber();
    const budgetMin = lead.budgetMin ? lead.budgetMin.toNumber() : 0;

    // Dépasse le budget max = bloqué
    if (propPrice > budgetMax) {
      return {
        score: 0,
        matched: false,
        reason: `Price ${propPrice}€ exceeds budget max ${budgetMax}€`,
        blocked: this.config.blocking.blockIfBudgetExceeded,
      };
    }

    // En dessous du budget min = moins optimal
    if (propPrice < budgetMin) {
      return {
        score: 50,
        matched: false,
        reason: `Price ${propPrice}€ below minimum ${budgetMin}€`,
        blocked: false,
      };
    }

    // Dans la fourchette
    const budgetRange = budgetMax - budgetMin;
    if (budgetRange === 0) {
      return {
        score: propPrice === budgetMax ? 100 : 80,
        matched: true,
        reason: `Price ${propPrice}€ matches exact budget`,
        blocked: false,
      };
    }

    // Scoring selon proximité avec le max du budget
    const distanceFromMax = budgetMax - propPrice;
    const percentageOfRange = (distanceFromMax / budgetRange) * 100;

    // Plus proche du max = mieux
    const score = 100 - (percentageOfRange / 100) * 20;
    const finalScore = Math.max(score, 80); // Minimum 80 si dans la range

    return {
      score: finalScore,
      matched: true,
      reason: `Price ${propPrice}€ within budget ${budgetMin}€ - ${budgetMax}€`,
      blocked: false,
    };
  }

  /**
   * ÉTAPE 6: Scoring - Surface
   */
  private scoreSurface(lead: Lead, property: Property): {
    score: number;
    matched: boolean;
    reason: string;
    blocked: boolean;
  } {
    if (!property.surface) {
      return {
        score: 70,
        matched: true,
        reason: "Surface not specified for property",
        blocked: false,
      };
    }

    const propSurface = property.surface;
    const surfaceMin = lead.surfaceMin || 0;
    const surfaceMax = lead.surfaceMax;

    // Trop petit = bloqué si mandatory
    if (propSurface < surfaceMin && surfaceMin > 0) {
      return {
        score: 0,
        matched: false,
        reason: `Surface ${propSurface}m² below minimum ${surfaceMin}m²`,
        blocked: true,
      };
    }

    // Trop grand = moins optimal
    if (surfaceMax && propSurface > surfaceMax) {
      return {
        score: 50,
        matched: false,
        reason: `Surface ${propSurface}m² exceeds maximum ${surfaceMax}m²`,
        blocked: false,
      };
    }

    // Dans la fourchette
    if (surfaceMin === 0) {
      return {
        score: 85,
        matched: true,
        reason: "No surface requirement specified",
        blocked: false,
      };
    }

    const excess = propSurface - surfaceMin;
    const thirtyPercentOfMin = surfaceMin * 0.3;

    if (excess > thirtyPercentOfMin) {
      return {
        score: 90,
        matched: true,
        reason: `Surface ${propSurface}m² exceeds minimum by >30%`,
        blocked: false,
      };
    }

    const score = 95 + (excess / surfaceMin) * 5;
    return {
      score: Math.min(score, 100),
      matched: true,
      reason: `Surface ${propSurface}m² matches minimum requirement`,
      blocked: false,
    };
  }

  /**
   * ÉTAPE 7: Scoring - Chambres
   */
  private scoreBedrooms(lead: Lead, property: Property): {
    score: number;
    matched: boolean;
    reason: string;
    blocked: boolean;
  } {
    if (!lead.bedroomsMin) {
      return {
        score: 80,
        matched: true,
        reason: "No bedroom requirement specified",
        blocked: false,
      };
    }

    if (!property.bedrooms) {
      return {
        score: 70,
        matched: true,
        reason: "Bedrooms not specified for property",
        blocked: false,
      };
    }

    const propBedrooms = property.bedrooms;
    const minBedrooms = lead.bedroomsMin;

    // Trop peu de chambres = bloqué
    if (propBedrooms < minBedrooms) {
      return {
        score: 0,
        matched: false,
        reason: `${propBedrooms} bedroom(s) below minimum ${minBedrooms}`,
        blocked: true,
      };
    }

    // Exact match
    if (propBedrooms === minBedrooms) {
      return {
        score: 100,
        matched: true,
        reason: `Exact bedroom match: ${propBedrooms}`,
        blocked: false,
      };
    }

    // Une chambre de plus = acceptable
    if (propBedrooms === minBedrooms + 1) {
      return {
        score: 95,
        matched: true,
        reason: `${propBedrooms} bedroom(s): +1 from minimum`,
        blocked: false,
      };
    }

    // Plus de chambres = moins optimal
    return {
      score: 85,
      matched: true,
      reason: `${propBedrooms} bedroom(s): ${propBedrooms - minBedrooms} more than minimum`,
      blocked: false,
    };
  }

  /**
   * ÉTAPE 8: Scoring - Équipements
   */
  private scoreEquipments(
    preferences: Array<{
      criteriaKey: string;
      value: string;
      importance: string;
    }>,
    property: Property
  ): {
    score: number;
    matched: boolean;
    reasons: string[];
    warnings: string[];
  } {
    const equipmentMap: Record<
      string,
      (property: Property) => boolean | null
    > = {
      parking: (p) => p.hasParking,
      balcony: (p) => p.hasBalcony,
      terrace: (p) => p.hasTerrrace,
      garden: (p) => p.hasGarden,
      elevator: (p) => p.hasElevator,
      cellar: (p) => p.hasCellar,
      furnished: (p) => p.isFurnished,
    };

    const scores: number[] = [];
    const reasons: string[] = [];
    const warnings: string[] = [];
    let blockedByEquipment = false;

    for (const pref of preferences) {
      const equipmentCheck = equipmentMap[pref.criteriaKey];
      if (!equipmentCheck) continue;

      const hasEquipment = equipmentCheck(property);
      if (hasEquipment === null) continue;

      const value = pref.value.toLowerCase() === "true";

      // Si l'équipement est recherché
      if (value) {
        if (pref.importance === "mandatory") {
          if (!hasEquipment) {
            blockedByEquipment = true;
            warnings.push(`${pref.criteriaKey}_missing`);
            scores.push(0);
          } else {
            reasons.push(`${pref.criteriaKey}_available`);
            scores.push(100);
          }
        } else if (pref.importance === "important") {
          if (hasEquipment) {
            reasons.push(`${pref.criteriaKey}_available`);
            scores.push(100);
          } else {
            warnings.push(`${pref.criteriaKey}_missing`);
            scores.push(60);
          }
        } else if (pref.importance === "preferred") {
          if (hasEquipment) {
            reasons.push(`${pref.criteriaKey}_available`);
            scores.push(100);
          } else {
            warnings.push(`${pref.criteriaKey}_missing`);
            scores.push(80);
          }
        }
      }
    }

    const avgScore = scores.length > 0 ? scores.reduce((a, b) => a + b) / scores.length : 80;
    let finalScore = avgScore;

    // Pénalité si trop de warnings
    if (warnings.length > 2) {
      finalScore -= 10;
    }

    return {
      score: Math.max(0, Math.min(100, finalScore)),
      matched: !blockedByEquipment,
      reasons,
      warnings,
    };
  }

  /**
   * CALCUL DU SCORE FINAL
   * Applique les poids et retourne un score 0-100
   */
  private calculateFinalScore(criteria: Record<string, CriteriaScore>): number {
    const criteriasWithWeights = Object.values(criteria).filter(
      (c) => c.weight > 0
    );

    const totalWeight = criteriasWithWeights.reduce((sum, c) => sum + c.weight, 0);
    const weightedSum = criteriasWithWeights.reduce(
      (sum, c) => sum + c.score * c.weight,
      0
    );

    if (totalWeight === 0) return 0;

    const score = weightedSum / totalWeight;
    return Math.round(score * 10) / 10; // Round to 1 decimal
  }

  /**
   * MAIN METHOD: Calculate match between lead and property
   */
  public calculateMatch(
    lead: Lead & { leadCities: { cityId: number }[] },
    property: Property,
    agencyId: number,
    preferences: Array<{
      criteriaKey: string;
      value: string;
      importance: string;
    }> = []
  ): MatchResult {
    const startTime = Date.now();
    const criteria: Record<string, CriteriaScore> = {};
    const reasons: string[] = [];
    const warnings: string[] = [];
    let isEligible = true;

    // ========================================================================
    // 1. VALIDATION MULTI-TENANT
    // ========================================================================

    const validation = this.validateMultiTenant(lead, property, agencyId);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    // ========================================================================
    // 2. FILTRES BLOQUANTS
    // ========================================================================

    // Transaction type
    const transactionType = this.scoreTransactionType(lead, property);
    criteria["transaction_type"] = {
      name: "Transaction Type",
      score: transactionType.score,
      weight: 0, // Pas compté dans le score final
      matched: transactionType.matched,
      reason: transactionType.reason,
    };
    if (transactionType.blocked) {
      isEligible = false;
      warnings.push("transaction_type_mismatch");
    }

    // Property type
    const propertyType = this.scorePropertyType(lead, property);
    criteria["property_type"] = {
      name: "Property Type",
      score: propertyType.score,
      weight: this.config.weights.propertyType,
      matched: propertyType.matched,
      reason: propertyType.reason,
    };
    if (propertyType.blocked) {
      isEligible = false;
      warnings.push("property_type_mismatch");
    } else if (propertyType.matched) {
      reasons.push("property_type_match");
    }

    // City
    const leadCityIds = lead.leadCities.map((lc) => lc.cityId);
    const city = this.scoreCity(leadCityIds, property);
    criteria["city"] = {
      name: "City",
      score: city.score,
      weight: this.config.weights.city,
      matched: city.matched,
      reason: city.reason,
    };
    if (city.blocked) {
      isEligible = false;
      warnings.push("city_mismatch");
    } else if (city.matched) {
      reasons.push("city_match");
    }

    // Budget
    const budget = this.scoreBudget(lead, property);
    criteria["budget"] = {
      name: "Budget",
      score: budget.score,
      weight: this.config.weights.budget,
      matched: budget.matched,
      reason: budget.reason,
    };
    if (budget.blocked) {
      isEligible = false;
      warnings.push("budget_exceeded");
    } else if (budget.matched) {
      reasons.push("budget_match");
    }

    // ========================================================================
    // 3. SCORING (Une fois les filtres bloquants passés)
    // ========================================================================

    // Surface
    const surface = this.scoreSurface(lead, property);
    criteria["surface"] = {
      name: "Surface",
      score: surface.score,
      weight: this.config.weights.surface,
      matched: surface.matched,
      reason: surface.reason,
    };
    if (surface.blocked) {
      isEligible = false;
      warnings.push("surface_insufficient");
    } else if (surface.matched) {
      reasons.push("surface_match");
    }

    // Bedrooms
    const bedrooms = this.scoreBedrooms(lead, property);
    criteria["bedrooms"] = {
      name: "Bedrooms",
      score: bedrooms.score,
      weight: this.config.weights.bedrooms,
      matched: bedrooms.matched,
      reason: bedrooms.reason,
    };
    if (bedrooms.blocked) {
      isEligible = false;
      warnings.push("bedrooms_insufficient");
    } else if (bedrooms.matched) {
      reasons.push("bedrooms_match");
    }

    // Equipments
    const equipments = this.scoreEquipments(preferences, property);
    criteria["equipments"] = {
      name: "Equipments",
      score: equipments.score,
      weight: this.config.weights.equipments,
      matched: equipments.matched,
      reason: "Equipments scoring",
    };
    if (!equipments.matched) {
      isEligible = false;
    }
    reasons.push(...equipments.reasons);
    warnings.push(...equipments.warnings);

    // ========================================================================
    // 4. CALCUL DU SCORE FINAL
    // ========================================================================

    const finalScore = isEligible ? this.calculateFinalScore(criteria) : 0;

    // ========================================================================
    // 5. RETOUR
    // ========================================================================

    return {
      leadId: lead.id,
      propertyId: property.id,
      agencyId,
      score: finalScore,
      eligible: isEligible,
      criteria,
      reasons: [...new Set(reasons)], // Unique
      warnings: [...new Set(warnings)], // Unique
      calculationTimeMs: Date.now() - startTime,
      timestamp: new Date(),
    };
  }
}

// ============================================================================
// EXPORT SINGLETON
// ============================================================================

export const matchingEngine = new MatchingEngine();
