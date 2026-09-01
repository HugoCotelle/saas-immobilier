/**
 * PROPERTY SERVICE
 * 
 * Responsable de:
 * - CRUD des biens
 * - Statut des biens
 * - Rematching quand un bien est ajouté/modifié
 */

import { PrismaClient, Property } from "@prisma/client";
import { MatchingService } from "./matching.service";

export interface CreatePropertyInput {
  agencyId: number;
  reference: string;
  title: string;
  transactionType: "sale" | "rent";
  propertyType: string;
  cityId: number;
  address: string;
  postalCode?: string;
  price: number;
  surface?: number;
  rooms?: number;
  bedrooms?: number;
  bathrooms?: number;
  floor?: number;
  hasElevator?: boolean;
  hasBalcony?: boolean;
  hasTerrrace?: boolean;
  hasGarden?: boolean;
  hasParking?: boolean;
  hasCellar?: boolean;
  isFurnished?: boolean;
  availabilityDate?: Date;
  description?: string;
  mainPhotoUrl?: string;
  assignedAgentId?: number;
}

export class PropertyService {
  private prisma: PrismaClient;
  private matchingService: MatchingService;

  constructor(prisma: PrismaClient, matchingService: MatchingService) {
    this.prisma = prisma;
    this.matchingService = matchingService;
  }

  /**
   * Créer un nouveau bien
   * Déclenche automatiquement le rematching avec les leads existants
   */
  async createProperty(input: CreatePropertyInput): Promise<Property> {
    // 1. Vérifier que la référence est unique pour cette agence
    const existing = await this.prisma.property.findFirst({
      where: {
        agencyId: input.agencyId,
        reference: input.reference,
      },
    });

    if (existing) {
      throw new Error(
        `Property with reference ${input.reference} already exists in this agency`
      );
    }

    // 2. Vérifier que la ville existe
    const city = await this.prisma.city.findUnique({
      where: { id: input.cityId },
    });

    if (!city) {
      throw new Error("City not found");
    }

    // 3. Vérifier que l'agence a accès à cette ville
    const agencyCity = await this.prisma.agencyCity.findFirst({
      where: {
        agencyId: input.agencyId,
        cityId: input.cityId,
      },
    });

    if (!agencyCity) {
      throw new Error("Agency does not operate in this city");
    }

    // 4. Créer le bien
    const property = await this.prisma.property.create({
      data: {
        agencyId: input.agencyId,
        reference: input.reference,
        title: input.title,
        transactionType: input.transactionType,
        propertyType: input.propertyType,
        cityId: input.cityId,
        address: input.address,
        postalCode: input.postalCode,
        price: input.price,
        surface: input.surface,
        rooms: input.rooms,
        bedrooms: input.bedrooms,
        bathrooms: input.bathrooms,
        floor: input.floor,
        hasElevator: input.hasElevator || false,
        hasBalcony: input.hasBalcony || false,
        hasTerrrace: input.hasTerrrace || false,
        hasGarden: input.hasGarden || false,
        hasParking: input.hasParking || false,
        hasCellar: input.hasCellar || false,
        isFurnished: input.isFurnished || false,
        availabilityDate: input.availabilityDate,
        description: input.description,
        mainPhotoUrl: input.mainPhotoUrl,
        assignedAgentId: input.assignedAgentId,
        status: "available",
      },
    });

    // 5. DÉCLENCHER LE REMATCHING (EVENT-DRIVEN)
    // Trouver tous les leads compatibles et les reMatcher
    await this.matchingService.matchPropertyWithLeads(
      property,
      input.agencyId
    );

    return property;
  }

  /**
   * Récupérer un bien
   */
  async getProperty(propertyId: number, agencyId: number): Promise<Property | null> {
    return this.prisma.property.findFirst({
      where: { id: propertyId, agencyId },
    });
  }

  /**
   * Lister les biens d'une agence
   */
  async listProperties(
    agencyId: number,
    options: {
      status?: string;
      transactionType?: string;
      cityId?: number;
      skip?: number;
      take?: number;
    } = {}
  ): Promise<Property[]> {
    const where: any = { agencyId };

    if (options.status) {
      where.status = options.status;
    }

    if (options.transactionType) {
      where.transactionType = options.transactionType;
    }

    if (options.cityId) {
      where.cityId = options.cityId;
    }

    return this.prisma.property.findMany({
      where,
      skip: options.skip || 0,
      take: options.take || 50,
      orderBy: { createdAt: "desc" },
    });
  }

  /**
   * Mettre à jour le statut d'un bien
   */
  async updatePropertyStatus(
    propertyId: number,
    agencyId: number,
    status: string
  ): Promise<Property> {
    const property = await this.getProperty(propertyId, agencyId);

    if (!property) {
      throw new Error("Property not found");
    }

    return this.prisma.property.update({
      where: { id: propertyId },
      data: { status, updatedAt: new Date() },
    });
  }

  /**
   * Modifier les détails d'un bien
   */
  async updateProperty(
    propertyId: number,
    agencyId: number,
    updates: Partial<CreatePropertyInput>
  ): Promise<Property> {
    const property = await this.getProperty(propertyId, agencyId);

    if (!property) {
      throw new Error("Property not found");
    }

    return this.prisma.property.update({
      where: { id: propertyId },
      data: {
        ...updates,
        updatedAt: new Date(),
      },
    });
  }

  /**
   * Supprimer un bien
   */
  async deleteProperty(propertyId: number, agencyId: number): Promise<Property> {
    const property = await this.getProperty(propertyId, agencyId);

    if (!property) {
      throw new Error("Property not found");
    }

    // Les matchs seront supprimés automatiquement (onDelete: Cascade)
    return this.prisma.property.delete({
      where: { id: propertyId },
    });
  }

  /**
   * Assigner un bien à un agent
   */
  async assignPropertyToAgent(
    propertyId: number,
    agencyId: number,
    agentId: number
  ): Promise<Property> {
    // Vérifier que l'agent existe et appartient à l'agence
    const agent = await this.prisma.user.findFirst({
      where: { id: agentId, agencyId },
    });

    if (!agent) {
      throw new Error("Agent not found in this agency");
    }

    return this.prisma.property.update({
      where: { id: propertyId },
      data: { assignedAgentId: agentId, updatedAt: new Date() },
    });
  }

  /**
   * Récupérer les biens avec leurs meilleurs leads correspondants
   * (Vue dashboard)
   */
  async getPropertiesWithMatches(
    agencyId: number,
    limit: number = 10
  ): Promise<
    Array<
      Property & {
        topMatches: Array<{
          score: number;
          lead: any;
        }>;
        matchCount: number;
      }
    >
  > {
    const properties = await this.prisma.property.findMany({
      where: {
        agencyId,
        status: "available",
      },
      include: {
        matches: {
          where: { eligible: true },
          orderBy: { score: "desc" },
          take: 5,
          include: { lead: true },
        },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    return properties.map((prop) => ({
      ...prop,
      topMatches: prop.matches.map((m) => ({
        score: m.score.toNumber(),
        lead: m.lead,
      })),
      matchCount: prop.matches.length,
    }));
  }

  /**
   * Compter les biens par statut
   */
  async getPropertyStatsCounts(agencyId: number): Promise<Record<string, number>> {
    const statuses = ["available", "reserved", "under_offer", "sold", "rented", "inactive"];

    const counts: Record<string, number> = {};

    for (const status of statuses) {
      const count = await this.prisma.property.count({
        where: { agencyId, status },
      });
      counts[status] = count;
    }

    return counts;
  }

  /**
   * Importer des biens depuis CSV/Excel
   * Format: reference, title, transactionType, propertyType, price, surface, bedrooms, city, address
   */
  async importPropertiesFromCSV(
    agencyId: number,
    rows: CreatePropertyInput[]
  ): Promise<{
    success: number;
    failed: number;
    errors: Array<{ row: number; error: string }>;
  }> {
    let success = 0;
    let failed = 0;
    const errors: Array<{ row: number; error: string }> = [];

    for (let i = 0; i < rows.length; i++) {
      try {
        await this.createProperty({ ...rows[i], agencyId });
        success++;
      } catch (error) {
        failed++;
        errors.push({
          row: i + 1,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }

    return { success, failed, errors };
  }
}
