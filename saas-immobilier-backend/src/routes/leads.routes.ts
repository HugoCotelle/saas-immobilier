/**
 * API ROUTES: LEADS
 * 
 * Endpoints pour:
 * - Créer un lead
 * - Récupérer les leads
 * - Mettre à jour un lead
 * - Attribuer à un agent
 * - Ajouter des préférences
 * - Voir les matchs
 */

import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { authenticateJWT, enforceAgencyContext, AuthenticatedRequest } from "@middleware/auth.middleware";
import { LeadService } from "@services/lead.service";
import { MatchingService } from "@services/matching.service";

const router = Router();
const prisma = new PrismaClient();
const matchingService = new MatchingService(prisma);
const leadService = new LeadService(prisma, matchingService);

// ============================================================================
// POST /api/leads - Créer un lead
// ============================================================================
router.post(
  "/",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const {
        firstName,
        lastName,
        email,
        phone,
        source,
        transactionType,
        propertyType,
        budgetMin,
        budgetMax,
        surfaceMin,
        surfaceMax,
        bedroomsMin,
        bedroomsMax,
        cities,
        preferences,
        assignedAgentId,
      } = req.body;

      // Validation de base
      if (!firstName || !lastName || !budgetMax || !cities || cities.length === 0) {
        return res.status(400).json({
          error: "Missing required fields: firstName, lastName, budgetMax, cities",
        });
      }

      const lead = await leadService.createLead({
        agencyId: req.user.agencyId,
        firstName,
        lastName,
        email,
        phone,
        source: source || "manual",
        transactionType: transactionType || "rent",
        propertyType: propertyType || "apartment",
        budgetMin: budgetMin ? parseFloat(budgetMin) : undefined,
        budgetMax: parseFloat(budgetMax),
        surfaceMin,
        surfaceMax,
        bedroomsMin,
        bedroomsMax,
        cities,
        preferences: preferences || [],
        assignedAgentId,
      });

      return res.status(201).json({
        success: true,
        lead,
      });
    } catch (error) {
      console.error("Error creating lead:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to create lead",
      });
    }
  }
);

// ============================================================================
// GET /api/leads - Lister les leads
// ============================================================================
router.get(
  "/",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { status, skip, take } = req.query;

      const leads = await leadService.listLeads(req.user.agencyId, {
        status: status as string,
        skip: skip ? parseInt(skip as string) : 0,
        take: take ? parseInt(take as string) : 50,
      });

      const counts = await leadService.getLeadStatsCounts(req.user.agencyId);

      return res.json({
        leads,
        counts,
      });
    } catch (error) {
      console.error("Error listing leads:", error);
      return res.status(500).json({
        error: "Failed to list leads",
      });
    }
  }
);

// ============================================================================
// GET /api/leads/:leadId - Récupérer un lead avec matchs
// ============================================================================
router.get(
  "/:leadId",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { leadId } = req.params;
      const leadIdNum = parseInt(leadId);

      const lead = await leadService.getLead(leadIdNum, req.user.agencyId);

      if (!lead) {
        return res.status(404).json({ error: "Lead not found" });
      }

      // Récupérer les matchs
      const matches = await matchingService.getLeadMatches(
        leadIdNum,
        req.user.agencyId,
        10
      );

      return res.json({
        lead,
        matches: matches.map((m) => ({
          score: m.match.score,
          property: m.property,
          matchDetails: m.match.matchDetails,
        })),
      });
    } catch (error) {
      console.error("Error retrieving lead:", error);
      return res.status(500).json({
        error: "Failed to retrieve lead",
      });
    }
  }
);

// ============================================================================
// PUT /api/leads/:leadId/status - Mettre à jour le statut
// ============================================================================
router.put(
  "/:leadId/status",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { leadId } = req.params;
      const { status } = req.body;

      if (!status) {
        return res.status(400).json({ error: "Missing status" });
      }

      const lead = await leadService.updateLeadStatus(
        parseInt(leadId),
        req.user.agencyId,
        status
      );

      return res.json({
        success: true,
        lead,
      });
    } catch (error) {
      console.error("Error updating lead status:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to update status",
      });
    }
  }
);

// ============================================================================
// PUT /api/leads/:leadId/assign - Assigner à un agent
// ============================================================================
router.put(
  "/:leadId/assign",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { leadId } = req.params;
      const { agentId } = req.body;

      if (!agentId) {
        return res.status(400).json({ error: "Missing agentId" });
      }

      const lead = await leadService.assignLeadToAgent(
        parseInt(leadId),
        req.user.agencyId,
        agentId
      );

      return res.json({
        success: true,
        lead,
      });
    } catch (error) {
      console.error("Error assigning lead:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to assign lead",
      });
    }
  }
);

// ============================================================================
// POST /api/leads/:leadId/cities - Ajouter une ville
// ============================================================================
router.post(
  "/:leadId/cities",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { leadId } = req.params;
      const { cityId, priority } = req.body;

      if (!cityId) {
        return res.status(400).json({ error: "Missing cityId" });
      }

      const leadCity = await leadService.addCityToLead(
        parseInt(leadId),
        req.user.agencyId,
        cityId,
        priority || "preferred"
      );

      return res.status(201).json({
        success: true,
        leadCity,
      });
    } catch (error) {
      console.error("Error adding city to lead:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to add city",
      });
    }
  }
);

// ============================================================================
// POST /api/leads/:leadId/preferences - Ajouter une préférence
// ============================================================================
router.post(
  "/:leadId/preferences",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { leadId } = req.params;
      const { criteriaKey, value, importance } = req.body;

      if (!criteriaKey || !value || !importance) {
        return res.status(400).json({
          error: "Missing required fields: criteriaKey, value, importance",
        });
      }

      const preference = await leadService.addPreferenceToLead(
        parseInt(leadId),
        req.user.agencyId,
        criteriaKey,
        value,
        importance
      );

      return res.status(201).json({
        success: true,
        preference,
      });
    } catch (error) {
      console.error("Error adding preference:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to add preference",
      });
    }
  }
);

// ============================================================================
// POST /api/leads/:leadId/activities - Enregistrer une activité
// ============================================================================
router.post(
  "/:leadId/activities",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { leadId } = req.params;
      const { actionType, description } = req.body;

      if (!actionType) {
        return res.status(400).json({ error: "Missing actionType" });
      }

      const activity = await leadService.recordActivity(
        parseInt(leadId),
        req.user.agencyId,
        req.user.id,
        actionType,
        description
      );

      return res.status(201).json({
        success: true,
        activity,
      });
    } catch (error) {
      console.error("Error recording activity:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to record activity",
      });
    }
  }
);

// ============================================================================
// GET /api/leads/dashboard/overview - Dashboard avec tops matchs
// ============================================================================
router.get(
  "/dashboard/overview",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const leadsWithMatches = await leadService.getLeadsWithMatches(
        req.user.agencyId,
        10
      );

      const stats = await leadService.getLeadStatsCounts(req.user.agencyId);

      const matchingStats = await matchingService.getMatchingStats(
        req.user.agencyId
      );

      return res.json({
        leads: leadsWithMatches,
        stats,
        matchingStats,
      });
    } catch (error) {
      console.error("Error fetching dashboard:", error);
      return res.status(500).json({
        error: "Failed to fetch dashboard",
      });
    }
  }
);

export default router;
