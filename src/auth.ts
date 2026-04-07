import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error("Missing JWT_SECRET");
}

export function signToken(userId: string) {
  return jwt.sign({ sub: userId, role: "candidate" }, jwtSecret, { expiresIn: "7d" });
}

export function signAdminToken(role: string) {
  return jwt.sign({ sub: "admin", role }, jwtSecret, { expiresIn: "12h" });
}

export type AuthedRequest = Request & { userId?: string };

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const token = auth.slice(7);
    const payload = jwt.verify(token, jwtSecret) as { sub: string; role?: string };
    req.userId = payload.sub;
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

export function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const token = auth.slice(7);
    const payload = jwt.verify(token, jwtSecret) as { sub: string; role?: string };
    const role = payload.role || "";
    if (!["admin", "superadmin", "hr"].includes(role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

export function requireSuperAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const token = auth.slice(7);
    const payload = jwt.verify(token, jwtSecret) as { sub: string; role?: string };
    if (payload.role !== "superadmin") {
      return res.status(403).json({ error: "Superadmin only" });
    }
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}
