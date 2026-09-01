/**
 * LEAD SERVICE
 * 
 * Responsable de:
 * - CRUD des leads
 * - Villes recherchées
 * - Préférences du lead
 * - Déclenchement du matching quand un lead arrive
 */

import { PrismaClient, Lead, LeadCity, LeadPreference } from "@prisma/client";
import { matchingEngine } from "./matching.engine";
import { MatchingService } from "./matching.service";

export interface CreateLeadInput {
  agencyId: number;
  firstName: string;
  lastName: string;
  email?: string;
  phone?: string;
  source: string;
  transactionType: "sale" | "rent";
  propertyType: string;
  budgetMin?: number;
  budgetMax: number;
  surfaceMin?: number;
  surfaceMax?: number;
  bedroomsMin?: number;
  bedroomsMax?: number;
  availabilityDate?: Date;
  furnishedRequired?: boolean;
  notes?: string;
  priority?: "very_hot" | "hot" | "normal" | "low";
}

export interface LeadWithDetails extends Lead {
  leadCities: LeadCity[];
  preferences: LeadPreference[];
}

export class LeadService {
  private prisma: PrismaClient;
  private matchingService: MatchingService;

  constructor(prisma: PrismaClient, matchingService: MatchingService) {
    this.prisma = prisma;
    this.matchingService = matchingService;
  }

  /**
   * Créer un nouveau lead
   * Déclenche automatiquement le matching
   */
  async createLead(
    input: CreateLeadInput & {
      cities: number[];
      preferences?: Array<{
        criteriaKey: string;
        value: string;
        importance: "mandatory" | "important" | "preferred";
      }>;
      assignedAgentId?: number;
    }
  ): Promise<LeadWithDetails> {
    // 1. Créer le lead
    const lead = await this.prisma.lead.create({
      data: {
        firstName: input.firstName,
        lastName: input.lastName,
        email: input.email,
        phone: input.phone,
        agencyId: input.agencyId,
        source: input.source,
        transactionType: input.transactionType,
        propertyType: input.propertyType,
        budgetMin: input.budgetMin,
        budgetMax: input.budgetMax,
        surfaceMin: input.surfaceMin,
        surfaceMax: input.surfaceMax,
        bedroomsMin: input.bedroomsMin,
        bedroomsMax: input.bedroomsMax,
        availabilityDate: input.availabilityDate,
        furnishedRequired: input.furnishedRequired,
        notes: input.notes,
        priority: input.priority || "normal",
        assignedAgentId: input.assignedAgentId,
        status: "new",
      },
      include: {
        leadCities: true,
        preferences: true,
      },
    });

    // 2. Ajouter les villes recherchées
    await this.prisma.leadCity.createMany({
      data: input.cities.map((cityId) => ({
        leadId: lead.id,
        cityId,
        priority: "preferred",
      })),
    });

    // 3. Ajouter les préférences
    if (input.preferences && input.preferences.length > 0) {
      await this.prisma.leadPreference.createMany({
        data: input.preferences.map((pref) => ({
          leadId: lead.id,
          criteriaKey: pref.criteriaKey,
          value: pref.value,
          valueType: typeof pref.value === "string" ? "string" : "boolean",
          importance: pref.importance,
        })),
      });
    }

    // 4. Récupérer le lead complet
    const leadWithDetails = await this.getLead(lead.id, input.agencyId);
    if (!leadWithDetails) {
      throw new Error("Failed to retrieve created lead");
    }

    // 5. DÉCLENCHER LE MATCHING (EVENT-DRIVEN)
    // Ce matching est asynchrone via queue, mais on peut le faire sync pour la démo
    await this.matchingService.matchLeadWithProperties(
      leadWithDetails,
      input.agencyId
    );

    return leadWithDetails;
  }

  /**
   * Récupérer un lead avec tous ses détails
   */
  async getLead(leadId: number, agencyId: number): Promise<LeadWithDetails | null> {
    return this.prisma.lead.findFirst({
      where: { id: leadId, agencyId },
      include: {
        leadCities: true,
        preferences: true,
      },
    });
  }

  /**
   * Lister tous les leads d'une agence
   */
  async listLeads(
    agencyId: number,
    options: {
      status?: string;
      skip?: number;
      take?: number;
    } = {}
  ): Promise<LeadWithDetails[]> {
    const where: any = { agencyId };

    if (options.status) {
      where.status = options.status;
    }

    return this.prisma.lead.findMany({
      where,
      include: {
        leadCities: true,
        preferences: true,
      },
      skip: options.skip || 0,
      take: options.take || 50,
      orderBy: { createdAt: "desc" },
    });
  }

  /**
   * Mettre à jour le statut d'un lead
   */
  async updateLeadStatus(
    leadId: number,
    agencyId: number,
    status: string
  ): Promise<Lead> {
    const lead = await this.prisma.lead.findFirst({
      where: { id: leadId, agencyId },
    });

    if (!lead) {
      throw new Error("Lead not found");
    }

    // Enregistrer la date du premier contact
    let firstContactAt = lead.firstContactAt;
    if (status !== "new" && !firstContactAt) {
      firstContactAt = new Date();
    }

    return this.prisma.lead.update({
      where: { id: leadId },
      data: {
        status,
        firstContactAt,
        updatedAt: new Date(),
      },
    });
  }

  /**
   * Assigner un lead à un agent
   */
  async assignLeadToAgent(
    leadId: number,
    agencyId: number,
    agentId: number
  ): Promise<Lead> {
    // Vérifier que l'agent appartient à l'agence
    const agent = await this.prisma.user.findFirst({
      where: {
        id: agentId,
        agencyId,
        role: "agent",
      },
    });

    if (!agent) {
      throw new Error("Agent not found in this agency");
    }

    return this.prisma.lead.update({
      where: { id: leadId },
      data: {
        assignedAgentId: agentId,
        updatedAt: new Date(),
      },
    });
  }

  /**
   * Ajouter une ville à la recherche d'un lead
   */
  async addCityToLead(
    leadId: number,
    agencyId: number,
    cityId: number,
    priority: "preferred" | "acceptable" = "preferred"
  ): Promise<LeadCity> {
    const lead = await this.prisma.lead.findFirst({
      where: { id: leadId, agencyId },
    });

    if (!lead) {
      throw new Error("Lead not found");
    }

    // Checker que la ville existe
    const city = await this.prisma.city.findUnique({
      where: { id: cityId },
    });

    if (!city) {
      throw new Error("City not found");
    }

    // Créer ou mettre à jour la relation
    return this.prisma.leadCity.upsert({
      where: {
        leadId_cityId: { leadId, cityId },
      },
      update: { priority },
      create: { leadId, cityId, priority },
    });
  }

  /**
   * Ajouter une préférence au lead
   */
  async addPreferenceToLead(
    leadId: number,
    agencyId: number,
    criteriaKey: string,
    value: string,
    importance: "mandatory" | "important" | "preferred"
  ): Promise<LeadPreference> {
    const lead = await this.prisma.lead.findFirst({
      where: { id: leadId, agencyId },
    });

    if (!lead) {
      throw new Error("Lead not found");
    }

    // Vérifier le type de valeur
    const valueType =
      value.toLowerCase() === "true" || value.toLowerCase() === "false"
        ? "boolean"
        : isNaN(Number(value))
          ? "string"
          : "decimal";

    return this.prisma.leadPreference.create({
      data: {
        leadId,
        criteriaKey,
        value,
        valueType,
        importance,
      },
    });
  }

  /**
   * Enregistrer une activité du lead (call, email, etc.)
   */
  async recordActivity(
    leadId: number,
    agencyId: number,
    userId: number,
    actionType: string,
    description?: string
  ): Promise<any> {
    const lead = await this.prisma.lead.findFirst({
      where: { id: leadId, agencyId },
    });

    if (!lead) {
      throw new Error("Lead not found");
    }

    return this.prisma.leadActivity.create({
      data: {
        leadId,
        agencyId,
        userId,
        actionType,
        description,
      },
    });
  }

  /**
   * Récupérer les leads d'une agence avec leurs meilleurs matches
   * (Vue dashboard)
   */
  async getLeadsWithMatches(
    agencyId: number,
    limit: number = 10
  ): Promise<
    Array<
      LeadWithDetails & {
        topMatches: Array<{
          score: number;
          property: any;
        }>;
        matchCount: number;
      }
    >
  > {
    const leads = await this.prisma.lead.findMany({
      where: {
        agencyId,
        status: { in: ["new", "contacted", "qualified"] },
      },
      include: {
        leadCities: true,
        preferences: true,
        matches: {
          where: { eligible: true },
          orderBy: { score: "desc" },
          take: 5,
          include: { property: true },
        },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    return leads.map((lead) => ({
      ...lead,
      topMatches: lead.matches.map((m) => ({
        score: m.score.toNumber(),
        property: m.property,
      })),
      matchCount: lead.matches.length,
    }));
  }

  /**
   * Compter les leads par statut
   */
  async getLeadStatsCounts(agencyId: number): Promise<Record<string, number>> {
    const statuses = [
      "new",
      "contacted",
      "qualified",
      "properties_sent",
      "visit_scheduled",
      "offer",
      "won",
      "lost",
    ];

    const counts: Record<string, number> = {};

    for (const status of statuses) {
      const count = await this.prisma.lead.count({
        where: { agencyId, status },
      });
      counts[status] = count;
    }

    return counts;
  }
}
