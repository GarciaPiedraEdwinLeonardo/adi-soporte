import express from "express";
import cors from "cors";
import helmet from "helmet";

// Routes
import faqsRoutes from "./modules/faqs/faqs.routes.js";
import errorTypesRoutes from "./modules/error-types/error-types.routes.js";
import ticketsRoutes from "./modules/tickets/tickets.routes.js";
import areasRoutes from "./modules/areas/areas.routes.js";
import authRoutes from "./modules/auth/auth.routes.js";

const app = express();

// --- Middlewares globales ---
app.use(helmet());
app.use(cors());
app.use(express.json());

// --- Routes ---
app.use("/api/faqs", faqsRoutes);
app.use("/api/error-types", errorTypesRoutes);
app.use("/api/tickets", ticketsRoutes);
app.use("/api/areas", areasRoutes);
app.use("/api/auth", authRoutes);

// --- Health check ---
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// --- 404 ---
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint no encontrado" });
});

// --- Error handler global ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Error interno del servidor" });
});

export default app;
