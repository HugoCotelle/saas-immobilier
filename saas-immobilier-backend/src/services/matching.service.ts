/**
 * MATCHING SERVICE
 * 
 * Orchestration du moteur de matching
 * - Lead arrive → Matching synchrone ou asynchrone
 * - Bien arrive → Rematching avec tous les leads compatibles
 * - Sauvegarde des résultats dans la table `matches`
 * - Déclenchement des notifications
 */

import { PrismaClient, Lead, Property } from "@prisma/client";
import { matchingEngine, MatchResult } from "./matching.engine";

export class MatchingService {
  private prisma: PrismaClient;

  constructor(prisma: PrismaClient) {
    this.prisma = prisma;
  }

  /**
   * Matcher un lead entrant avec TOUTES les properties disponibles de l'agence
   * 
   * FLUX:
   * 1. Récupérer les properties valides (agence, statut, transaction type, villes)
   * 2. Pour chaque property, calculer le score via matchingEngine
   * 3. Sauvegarder les matches en DB
   * 4. Retourner les top 10
   */
  async matchLeadWithProperties(
    lead: Lead & { leadCities: { cityId: number }[] },
    agencyId: number
  ): Promise<{
    topMatches: MatchResult[];
    totalMatches: number;
    averageScore: number;
  }> {
    // 1. VALIDATION
    if (lead.agencyId !== agencyId) {
      throw new Error("Lead does not belong to this agency");
    }

    // 2. PRÉ-FILTRAGE AGRESSIF
    // Éliminer les candidates qui ne sont clairement pas compatibles
    const leadCityIds = lead.leadCities.map((lc) => lc.cityId);

    const candidates = await this.prisma.property.findMany({
      where: {
        agencyId,
        status: "available", // Seuls les biens disponibles
        transactionType: lead.transactionType,
        propertyType: lead.propertyType,
        cityId: { in: leadCityIds }, // Villes concernées
        // Autres filtres si pertinent
      },
      include: { city: true },
    });

    console.log(
      `[Matching] Lead #${lead.id} - Found ${candidates.length} candidate properties`
    );

    // 3. RÉCUPÉRER LES PRÉFÉRENCES DU LEAD
    const preferences = await this.prisma.leadPreference.findMany({
      where: { leadId: lead.id },
    });

    // 4. CALCULER LE SCORE POUR CHAQUE CANDIDATE
    const matchResults: MatchResult[] = [];

    for (const property of candidates) {
      try {
        const result = matchingEngine.calculateMatch(
          lead,
          property,
          agencyId,
          preferences.map((p) => ({
            criteriaKey: p.criteriaKey,
            value: p.value,
            importance: p.importance,
          }))
        );

        matchResults.push(result);
      } catch (error) {
        console.error(
          `[Matching Error] Lead #${lead.id} - Property #${property.id}:`,
          error
        );
        // Continuer avec les autres properties
      }
    }

    // 5. TRIER PAR SCORE (DESC) ET GARDER LES MEILLEURS
    const sortedMatches = matchResults
      .filter((m) => m.eligible) // Seulement les éligibles
      .sort((a, b) => b.score - a.score);

    const topMatches = sortedMatches.slice(0, 10);

    console.log(
      `[Matching] Lead #${lead.id} - Got ${topMatches.length} eligible matches`
    );

    // 6. SAUVEGARDER TOUS LES MATCHES EN BASE (Historique)
    for (const result of matchResults) {
      await this.prisma.match.upsert({
        where: {
          leadId_propertyId: {
            leadId: result.leadId,
            propertyId: result.propertyId,
          },
        },
        update: {
          score: result.score,
          eligible: result.eligible,
          matchDetails: result as any, // Stocker le résultat complet
          updatedAt: new Date(),
        },
        create: {
          leadId: result.leadId,
          propertyId: result.propertyId,
          agencyId: result.agencyId,
          score: result.score,
          eligible: result.eligible,
          matchDetails: result as any,
        },
      });
    }

    // 7. CALCULER LES STATS
    const avgScore =
      topMatches.length > 0
        ? topMatches.reduce((sum, m) => sum + m.score, 0) / topMatches.length
        : 0;

    return {
      topMatches,
      totalMatches: topMatches.length,
      averageScore: Math.round(avgScore * 10) / 10,
    };
  }

  /**
   * Rematching quand un bien arrive
   * 
   * FLUX:
   * 1. Récupérer TOUS les leads compatibles (agence, statut, transaction type, villes)
   * 2. Pour chaque lead, calculer le score via matchingEngine
   * 3. Sauvegarder les matches en DB
   * 4. Retourner les leads matchés + notification
   */
  async matchPropertyWithLeads(
    property: Property,
    agencyId: number
  ): Promise<{
    matchedLeads: Array<{ leadId: number; score: number }>;
    totalMatches: number;
    notification: string;
  }> {
    // 1. VALIDATION
    if (property.agencyId !== agencyId) {
      throw new Error("Property does not belong to this agency");
    }

    // 2. PRÉ-FILTRAGE AGRESSIF
    // Trouver tous les leads qui recherchent ce type et ce type de bien dans cette ville
    const compatibleLeads = await this.prisma.lead.findMany({
      where: {
        agencyId,
        status: { in: ["new", "contacted", "qualified"] }, // Leads actifs
        transactionType: property.transactionType,
        propertyType: property.propertyType,
        leadCities: {
          some: { cityId: property.cityId },
        },
      },
      include: { leadCities: true, preferences: true },
    });

    console.log(
      `[Rematching] Property #${property.id} - Found ${compatibleLeads.length} compatible leads`
    );

    // 3. CALCULER LE SCORE POUR CHAQUE LEAD
    const matchResults: Array<{ leadId: number; score: number }> = [];

    for (const lead of compatibleLeads) {
      try {
        const result = matchingEngine.calculateMatch(
          lead,
          property,
          agencyId,
          lead.preferences.map((p) => ({
            criteriaKey: p.criteriaKey,
            value: p.value,
            importance: p.importance,
          }))
        );

        // Sauvegarder en DB
        await this.prisma.match.upsert({
          where: {
            leadId_propertyId: {
              leadId: result.leadId,
              propertyId: result.propertyId,
            },
          },
          update: {
            score: result.score,
            eligible: result.eligible,
            matchDetails: result as any,
            updatedAt: new Date(),
          },
          create: {
            leadId: result.leadId,
            propertyId: result.propertyId,
            agencyId: result.agencyId,
            score: result.score,
            eligible: result.eligible,
            matchDetails: result as any,
          },
        });

        if (result.eligible && result.score >= 50) {
          matchResults.push({
            leadId: result.leadId,
            score: result.score,
          });
        }
      } catch (error) {
        console.error(
          `[Rematching Error] Property #${property.id} - Lead #${lead.id}:`,
          error
        );
      }
    }

    // 4. TRIER PAR SCORE
    const sortedMatches = matchResults.sort((a, b) => b.score - a.score);

    console.log(
      `[Rematching] Property #${property.id} - Got ${sortedMatches.length} matched leads`
    );

    // 5. GÉNÉRER LA NOTIFICATION
    let notification = "";
    if (sortedMatches.length > 0) {
      notification = `🏠 Nouveau bien correspondant à ${sortedMatches.length} lead(s) potentiel(s)`;
      if (sortedMatches.length === 1) {
        notification = `🏠 Nouveau bien correspondant à 1 lead potentiel`;
      }
    }

    return {
      matchedLeads: sortedMatches,
      totalMatches: sortedMatches.length,
      notification,
    };
  }

  /**
   * Récupérer tous les matches pour un lead (avec les properties)
   */
  async getLeadMatches(
    leadId: number,
    agencyId: number,
    limit: number = 10
  ): Promise<
    Array<{
      match: any;
      property: Property;
    }>
  > {
    // Vérifier que le lead existe
    const lead = await this.prisma.lead.findFirst({
      where: { id: leadId, agencyId },
    });

    if (!lead) {
      throw new Error("Lead not found");
    }

    const matches = await this.prisma.match.findMany({
      where: {
        leadId,
        eligible: true,
      },
      include: { property: true },
      orderBy: { score: "desc" },
      take: limit,
    });

    return matches;
  }

  /**
   * Récupérer tous les matches pour une property (avec les leads)
   */
  async getPropertyMatches(
    propertyId: number,
    agencyId: number,
    limit: number = 10
  ): Promise<
    Array<{
      match: any;
      lead: Lead;
    }>
  > {
    // Vérifier que la property existe
    const property = await this.prisma.property.findFirst({
      where: { id: propertyId, agencyId },
    });

    if (!property) {
      throw new Error("Property not found");
    }

    const matches = await this.prisma.match.findMany({
      where: {
        propertyId,
        eligible: true,
      },
      include: { lead: true },
      orderBy: { score: "desc" },
      take: limit,
    });

    return matches;
  }

  /**
   * Récalculer TOUS les matchings pour une agence
   * (Job de maintenance/rebuild)
   */
  async recalculateAllMatches(agencyId: number): Promise<{
    processed: number;
    created: number;
    updated: number;
  }> {
    console.log(`[Recalc] Starting full recalculation for agency ${agencyId}`);

    let processed = 0;
    let created = 0;
    let updated = 0;

    // 1. Récupérer tous les leads de l'agence
    const leads = await this.prisma.lead.findMany({
      where: { agencyId },
      include: { leadCities: true, preferences: true },
    });

    // 2. Pour chaque lead, faire le matching
    for (const lead of leads) {
      try {
        await this.matchLeadWithProperties(lead, agencyId);
        processed++;
      } catch (error) {
        console.error(`[Recalc Error] Lead #${lead.id}:`, error);
      }
    }

    console.log(
      `[Recalc] Completed: ${processed} leads processed, ${created} created, ${updated} updated`
    );

    return { processed, created, updated };
  }

  /**
   * Récupérer les statistiques de matching pour une agence
   */
  async getMatchingStats(agencyId: number): Promise<{
    totalMatches: number;
    leadsWithMatches: number;
    avgMatchScore: number;
    matchingRate: number; // % de leads avec au moins 1 match
  }> {
    // Matches totaux
    const totalMatches = await this.prisma.match.count({
      where: { agencyId, eligible: true },
    });

    // Leads avec au moins 1 match
    const leadsWithMatches = await this.prisma.match.findMany({
      where: { agencyId, eligible: true },
      select: { leadId: true },
      distinct: ["leadId"],
    });

    // Score moyen
    const avgResult = await this.prisma.match.aggregate({
      where: { agencyId, eligible: true },
      _avg: { score: true },
    });

    const avgMatchScore = avgResult._avg.score
      ? Math.round(avgResult._avg.score.toNumber() * 10) / 10
      : 0;

    // Taux de matching (leads avec matches / total leads)
    const totalLeads = await this.prisma.lead.count({
      where: { agencyId },
    });

    const matchingRate =
      totalLeads > 0
        ? Math.round((leadsWithMatches.length / totalLeads) * 100)
        : 0;

    return {
      totalMatches,
      leadsWithMatches: leadsWithMatches.length,
      avgMatchScore,
      matchingRate,
    };
  }
}
