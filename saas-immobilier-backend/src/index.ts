import express from "express";
import { PrismaClient } from "@prisma/client";

const app = express();
const prisma = new PrismaClient();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok", message: "Server is running" });
});

app.get("/api/v1/leads", async (_req, res) => {
  const leads = await prisma.lead.findMany();
  res.json({ leads });
});

const port = parseInt(process.env.PORT || '3001', 10);
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
