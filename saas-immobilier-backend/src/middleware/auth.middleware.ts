/**
 * MIDDLEWARE D'AUTHENTIFICATION & AUTORISATION
 * 
 * - Vérifier les JWT
 * - Vérifier les permissions par rôle
 * - Enforcer l'isolation multi-tenant
 */

import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-prod";

export interface AuthenticatedRequest extends Request {
  user: {
    id: number;
    email: string;
    agencyId: number;
    role: "admin" | "manager" | "agent";
  };
}

/**
 * Middleware: Vérifier le JWT et récupérer l'utilisateur
 */
export function authenticateJWT(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid authorization header" });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = {
      id: decoded.userId,
      email: decoded.email,
      agencyId: decoded.agencyId,
      role: decoded.role,
    };
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * Middleware: Vérifier le rôle de l'utilisateur
 */
export function authorizeRole(...allowedRoles: string[]) {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}

/**
 * Middleware: Vérifier que l'agencyId du paramètre match celui de l'utilisateur
 * (Isolation multi-tenant)
 */
export function enforceAgencyContext(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const agencyId = parseInt(req.params.agencyId || req.body.agencyId);

  if (!agencyId) {
    res.status(400).json({ error: "Missing agencyId" });
    return;
  }

  if (agencyId !== req.user.agencyId && req.user.role !== "admin") {
    res.status(403).json({ error: "Cannot access other agencies' data" });
    return;
  }

  // Ajouter l'agencyId au body pour simplifier les contrôleurs
  req.body.agencyId = req.user.agencyId;
  next();
}

/**
 * Générer un JWT
 */
export function generateToken(
  userId: number,
  email: string,
  agencyId: number,
  role: string
): string {
  return jwt.sign(
    {
      userId,
      email,
      agencyId,
      role,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
