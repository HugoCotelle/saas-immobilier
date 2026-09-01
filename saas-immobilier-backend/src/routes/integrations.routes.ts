/**
 * API ROUTES: INTEGRATIONS
 * 
 * Endpoints pour:
 * - Recevoir les webhooks des portails (Leboncoin, Seloger, etc.)
 * - Configurer les connexions aux portails
 * - Sync manuelles
 * - Voir le statut des intégrations
 */

import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import {
  authenticateJWT,
  enforceAgencyContext,
  AuthenticatedRequest,
} from "@middleware/auth.middleware";
import {
  IntegrationManager,
  LeboncoinConnector,
  SelogerConnector,
  BienIciConnector,
  GenericWebhookReceiver,
} from "@services/integrations.service";
import { LeadService } from "@services/lead.service";
import { MatchingService } from "@services/matching.service";

const router = Router();
const prisma = new PrismaClient();
const matchingService = new MatchingService(prisma);
const leadService = new LeadService(prisma, matchingService);
const integrationManager = new IntegrationManager(
  prisma,
  leadService,
  matchingService
);

// ============================================================================
// WEBHOOK ENDPOINTS (Non-authentifiés, sécurisés par signature)
// ============================================================================

/**
 * POST /api/v1/integrations/webhooks/leboncoin
 * Webhook reçu depuis Leboncoin
 * 
 * Sécurité: Vérifier X-Signature header
 */
router.post("/webhooks/leboncoin", async (req, res) => {
  try {
    // 1. Vérifier la signature du webhook (sécurité)
    const signature = req.headers["x-signature"] as string;
    if (!verifyLeboncoinSignature(req.body, signature)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    // 2. Extraire agency_id depuis la configuration
    // (ou depuis le webhook si disponible)
    const agencyId = req.body.agency_id || req.query.agency_id;
    if (!agencyId) {
      return res.status(400).json({ error: "Missing agency_id" });
    }

    // 3. Traiter le lead
    const result = await integrationManager.receiveWebhook(
      parseInt(agencyId as string),
      "leboncoin",
      req.body
    );

    if (!result.success) {
      // Si c'est un doublon, on le log mais on retourne 200 (on ne refait pas)
      if (result.error?.includes("already exists")) {
        console.log(`[Leboncoin] Duplicate lead ignored`);
        return res.json({ success: true, message: "Duplicate ignored" });
      }

      return res.status(400).json(result);
    }

    return res.json({
      success: true,
      leadId: result.leadId,
      message: "Lead imported successfully",
    });
  } catch (error) {
    console.error("[Leboncoin Webhook Error]", error);
    return res.status(500).json({
      error: "Failed to process webhook",
    });
  }
});

/**
 * POST /api/v1/integrations/webhooks/seloger
 * Webhook reçu depuis Seloger
 */
router.post("/webhooks/seloger", async (req, res) => {
  try {
    const signature = req.headers["x-signature"] as string;
    if (!verifySelogerSignature(req.body, signature)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const agencyId = req.body.agency_id || req.query.agency_id;
    if (!agencyId) {
      return res.status(400).json({ error: "Missing agency_id" });
    }

    const result = await integrationManager.receiveWebhook(
      parseInt(agencyId as string),
      "seloger",
      req.body
    );

    if (!result.success) {
      if (result.error?.includes("already exists")) {
        return res.json({ success: true, message: "Duplicate ignored" });
      }
      return res.status(400).json(result);
    }

    return res.json({
      success: true,
      leadId: result.leadId,
      message: "Lead imported successfully",
    });
  } catch (error) {
    console.error("[Seloger Webhook Error]", error);
    return res.status(500).json({
      error: "Failed to process webhook",
    });
  }
});

/**
 * POST /api/v1/integrations/webhooks/generic
 * Webhook générique pour n'importe quel portail
 */
router.post("/webhooks/generic", async (req, res) => {
  try {
    const agencyId = req.query.agency_id;
    const source = req.query.source as string;

    if (!agencyId || !source) {
      return res
        .status(400)
        .json({ error: "Missing agency_id or source" });
    }

    const result = await integrationManager.receiveWebhook(
      parseInt(agencyId as string),
      source,
      req.body
    );

    if (!result.success) {
      if (result.error?.includes("already exists")) {
        return res.json({ success: true, message: "Duplicate ignored" });
      }
      return res.status(400).json(result);
    }

    return res.json({
      success: true,
      leadId: result.leadId,
      message: "Lead imported successfully",
    });
  } catch (error) {
    console.error("[Generic Webhook Error]", error);
    return res.status(500).json({
      error: "Failed to process webhook",
    });
  }
});

// ============================================================================
// CONFIGURATION ENDPOINTS (Authentifiés)
// ============================================================================

/**
 * POST /api/v1/integrations/configure/:source
 * Configurer l'API key pour un portail
 * 
 * Ex: POST /api/v1/integrations/configure/leboncoin
 * Body: { apiKey: "xxx" }
 */
router.post(
  "/configure/:source",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { source } = req.params;
      const { apiKey } = req.body;

      if (!apiKey) {
        return res.status(400).json({ error: "Missing apiKey" });
      }

      // Créer le connecteur approprié
      let connector;

      switch (source) {
        case "leboncoin":
          connector = new LeboncoinConnector(apiKey, req.user.agencyId);
          break;
        case "seloger":
          connector = new SelogerConnector(apiKey, req.user.agencyId);
          break;
        case "bien_ici":
          connector = new BienIciConnector(apiKey, req.user.agencyId);
          break;
        default:
          return res.status(400).json({ error: "Unknown source" });
      }

      // Valider la connexion
      const isValid = await connector.validateConnection();
      if (!isValid) {
        return res.status(400).json({ error: "Invalid API key" });
      }

      // Sauvegarder la configuration en BD
      await prisma.integrationConfig.upsert({
        where: {
          agencyId_source: {
            agencyId: req.user.agencyId,
            source,
          },
        },
        update: {
          apiKey: encryptApiKey(apiKey), // Chiffrer!
          status: "connected",
          lastCheckAt: new Date(),
        },
        create: {
          agencyId: req.user.agencyId,
          source,
          apiKey: encryptApiKey(apiKey),
          status: "connected",
          lastCheckAt: new Date(),
        },
      });

      // Enregistrer le connecteur dans le manager
      integrationManager.registerConnector(req.user.agencyId, connector);

      return res.json({
        success: true,
        message: `${source} configured successfully`,
      });
    } catch (error) {
      console.error("Error configuring integration:", error);
      return res.status(500).json({
        error: "Failed to configure integration",
      });
    }
  }
);

/**
 * GET /api/v1/integrations/status
 * Voir le statut de toutes les intégrations configurées
 */
router.get(
  "/status",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const configs = await prisma.integrationConfig.findMany({
        where: { agencyId: req.user.agencyId },
        select: {
          source: true,
          status: true,
          lastCheckAt: true,
          errorMessage: true,
        },
      });

      return res.json({
        integrations: configs,
        totalConfigured: configs.length,
        totalConnected: configs.filter((c) => c.status === "connected").length,
      });
    } catch (error) {
      console.error("Error fetching integration status:", error);
      return res.status(500).json({
        error: "Failed to fetch integration status",
      });
    }
  }
);

/**
 * DELETE /api/v1/integrations/:source
 * Déconnecter une intégration
 */
router.delete(
  "/:source",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { source } = req.params;

      await prisma.integrationConfig.deleteMany({
        where: {
          agencyId: req.user.agencyId,
          source,
        },
      });

      return res.json({
        success: true,
        message: `${source} disconnected`,
      });
    } catch (error) {
      console.error("Error disconnecting integration:", error);
      return res.status(500).json({
        error: "Failed to disconnect integration",
      });
    }
  }
);

// ============================================================================
// MANUAL SYNC ENDPOINTS
// ============================================================================

/**
 * POST /api/v1/integrations/sync/:source
 * Forcer une sync manuelle depuis un portail
 * 
 * Ex: POST /api/v1/integrations/sync/leboncoin
 */
router.post(
  "/sync/:source",
  authenticateJWT,
  enforceAgencyContext,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { source } = req.params;

      console.log(`[Manual Sync] Starting sync from ${source}`);

      const result = await integrationManager.syncFromConnector(
        req.user.agencyId,
        source
      );

      return res.json({
        success: true,
        ...result,
        message: `Synced ${result.imported} leads from ${source}`,
      });
    } catch (error) {
      console.error("Error syncing:", error);
      return res.status(500).json({
        error: error instanceof Error ? error.message : "Failed to sync",
      });
    }
  }
);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function verifyLeboncoinSignature(body: any, signature: string): boolean {
  // Vérifier la signature HMAC-SHA256 de Leboncoin
  // À implémenter avec le webhook secret
  return true; // Placeholder
}

function verifySelogerSignature(body: any, signature: string): boolean {
  // Vérifier la signature HMAC-SHA256 de Seloger
  return true; // Placeholder
}

function encryptApiKey(apiKey: string): string {
  // Chiffrer l'API key avant de stocker en BD
  // Utiliser crypto ou une lib comme 'bcryptjs'
  return apiKey; // Placeholder
}

export default router;
