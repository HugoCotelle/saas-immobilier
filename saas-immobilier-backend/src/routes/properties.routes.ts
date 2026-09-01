/**
 * API ROUTES: PROPERTIES
 * 
 * Endpoints pour:
 * - Créer un bien
 * - Récupérer les biens
 * - Mettre à jour un bien
 * - Voir les leads correspondants
 * - Importer des biens
 */

import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { authenticateJWT, enforceAgencyContext, AuthenticatedRequest } from "@middleware/auth.middleware";
import { PropertyService } from "@services/property.service";
import { MatchingService } from "@services/matching.service";

const router = Router();
const prisma = new PrismaClient();
const matchingService = new MatchingService(prisma);
const propertyService = new PropertyService(prisma, matchingService);

// ============================================================================
// POST /api/properties - Créer un bien
// ============================================================================
router.post(
  "/",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const {
        reference,
        title,
        transactionType,
        propertyType,
        cityId,
        address,
        postalCode,
        price,
        surface,
        rooms,
        bedrooms,
        bathrooms,
        floor,
        hasElevator,
        hasBalcony,
        hasTerrrace,
        hasGarden,
        hasParking,
        hasCellar,
        isFurnished,
        availabilityDate,
        description,
        mainPhotoUrl,
        assignedAgentId,
      } = req.body;

      // Validation
      if (!reference || !title || !transactionType || !propertyType || !cityId || !address || !price) {
        return res.status(400).json({
          error:
            "Missing required fields: reference, title, transactionType, propertyType, cityId, address, price",
        });
      }

      const property = await propertyService.createProperty({
        agencyId: req.user.agencyId,
        reference,
        title,
        transactionType,
        propertyType,
        cityId,
        address,
        postalCode,
        price: parseFloat(price),
        surface: surface ? parseInt(surface) : undefined,
        rooms: rooms ? parseInt(rooms) : undefined,
        bedrooms: bedrooms ? parseInt(bedrooms) : undefined,
        bathrooms: bathrooms ? parseInt(bathrooms) : undefined,
        floor: floor ? parseInt(floor) : undefined,
        hasElevator: hasElevator || false,
        hasBalcony: hasBalcony || false,
        hasTerrrace: hasTerrrace || false,
        hasGarden: hasGarden || false,
        hasParking: hasParking || false,
        hasCellar: hasCellar || false,
        isFurnished: isFurnished || false,
        availabilityDate: availabilityDate ? new Date(availabilityDate) : undefined,
        description,
        mainPhotoUrl,
        assignedAgentId,
      });

      return res.status(201).json({
        success: true,
        property,
      });
    } catch (error) {
      console.error("Error creating property:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to create property",
      });
    }
  }
);

// ============================================================================
// GET /api/properties - Lister les biens
// ============================================================================
router.get(
  "/",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { status, transactionType, cityId, skip, take } = req.query;

      const properties = await propertyService.listProperties(
        req.user.agencyId,
        {
          status: status as string,
          transactionType: transactionType as string,
          cityId: cityId ? parseInt(cityId as string) : undefined,
          skip: skip ? parseInt(skip as string) : 0,
          take: take ? parseInt(take as string) : 50,
        }
      );

      const counts = await propertyService.getPropertyStatsCounts(req.user.agencyId);

      return res.json({
        properties,
        counts,
      });
    } catch (error) {
      console.error("Error listing properties:", error);
      return res.status(500).json({
        error: "Failed to list properties",
      });
    }
  }
);

// ============================================================================
// GET /api/properties/:propertyId - Récupérer un bien avec matchs
// ============================================================================
router.get(
  "/:propertyId",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { propertyId } = req.params;
      const propertyIdNum = parseInt(propertyId);

      const property = await propertyService.getProperty(
        propertyIdNum,
        req.user.agencyId
      );

      if (!property) {
        return res.status(404).json({ error: "Property not found" });
      }

      // Récupérer les matchs
      const matches = await matchingService.getPropertyMatches(
        propertyIdNum,
        req.user.agencyId,
        10
      );

      return res.json({
        property,
        matches: matches.map((m) => ({
          score: m.match.score,
          lead: m.lead,
          matchDetails: m.match.matchDetails,
        })),
      });
    } catch (error) {
      console.error("Error retrieving property:", error);
      return res.status(500).json({
        error: "Failed to retrieve property",
      });
    }
  }
);

// ============================================================================
// PUT /api/properties/:propertyId - Mettre à jour un bien
// ============================================================================
router.put(
  "/:propertyId",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { propertyId } = req.params;
      const updates = req.body;

      const property = await propertyService.updateProperty(
        parseInt(propertyId),
        req.user.agencyId,
        updates
      );

      return res.json({
        success: true,
        property,
      });
    } catch (error) {
      console.error("Error updating property:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to update property",
      });
    }
  }
);

// ============================================================================
// PUT /api/properties/:propertyId/status - Mettre à jour le statut
// ============================================================================
router.put(
  "/:propertyId/status",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { propertyId } = req.params;
      const { status } = req.body;

      if (!status) {
        return res.status(400).json({ error: "Missing status" });
      }

      const property = await propertyService.updatePropertyStatus(
        parseInt(propertyId),
        req.user.agencyId,
        status
      );

      return res.json({
        success: true,
        property,
      });
    } catch (error) {
      console.error("Error updating property status:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to update status",
      });
    }
  }
);

// ============================================================================
// PUT /api/properties/:propertyId/assign - Assigner à un agent
// ============================================================================
router.put(
  "/:propertyId/assign",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { propertyId } = req.params;
      const { agentId } = req.body;

      if (!agentId) {
        return res.status(400).json({ error: "Missing agentId" });
      }

      const property = await propertyService.assignPropertyToAgent(
        parseInt(propertyId),
        req.user.agencyId,
        agentId
      );

      return res.json({
        success: true,
        property,
      });
    } catch (error) {
      console.error("Error assigning property:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to assign property",
      });
    }
  }
);

// ============================================================================
// DELETE /api/properties/:propertyId - Supprimer un bien
// ============================================================================
router.delete(
  "/:propertyId",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { propertyId } = req.params;

      const property = await propertyService.deleteProperty(
        parseInt(propertyId),
        req.user.agencyId
      );

      return res.json({
        success: true,
        property,
      });
    } catch (error) {
      console.error("Error deleting property:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to delete property",
      });
    }
  }
);

// ============================================================================
// GET /api/properties/dashboard/overview - Dashboard avec tops matchs
// ============================================================================
router.get(
  "/dashboard/overview",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const propertiesWithMatches = await propertyService.getPropertiesWithMatches(
        req.user.agencyId,
        10
      );

      const stats = await propertyService.getPropertyStatsCounts(req.user.agencyId);

      return res.json({
        properties: propertiesWithMatches,
        stats,
      });
    } catch (error) {
      console.error("Error fetching properties dashboard:", error);
      return res.status(500).json({
        error: "Failed to fetch dashboard",
      });
    }
  }
);

export default router;
