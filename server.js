/**
 * TAHAMUZZA - Backend Express con 2FA y JWT
 * Portal seguro de acceso restringido con autenticación de dos factores
 * 
 * Características:
 * - Autenticación con JWT + Cookies HTTP-only
 * - 2FA TOTP con Speakeasy
 * - Bcryptjs para hash de contraseñas
 * - PostgreSQL para persistencia (adaptado para Railway)
 * - CORS habilitado
 */

import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcryptjs from "bcryptjs";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import cookieParser from "cookie-parser";
import path from "path";
import dotenv from "dotenv";
import pkg from "pg";
const { Pool } = pkg;

// ===== CONFIGURACIÓN =====
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "tu_clave_secreta_cambiar_en_produccion";
const JWT_EXPIRE = "7d";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("❌ FATAL: La variable DATABASE_URL no está configurada. Necesaria para Railway.");
  process.exit(1);
}

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: "*", credentials: true }));
app.use(express.static(path.resolve("public")));

// ===== BASE DE DATOS (PostgreSQL) =====
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initializeDatabase() {
  try {
    await pool.query("SELECT 1");
    console.log("[DB] ✅ Conectado a PostgreSQL");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        role TEXT DEFAULT 'user',
        "twoFASecret" TEXT,
        "twoFAEnabled" BOOLEAN DEFAULT FALSE,
        "twoFABackupCodes" TEXT,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS twofa_sessions (
        id SERIAL PRIMARY KEY,
        "userId" INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        "sessionToken" TEXT UNIQUE NOT NULL,
        "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("[DB] 🧱 Tablas inicializadas correctamente");
  } catch (err) {
    console.error("[DB] ❌ Error al conectar o inicializar la base de datos:", err);
    throw err; // Lanzamos para manejar el error arriba
  }
}

// ===== UTILIDADES =====
async function dbGet(sql, params) {
  const result = await pool.query(sql, params);
  return result.rows[0];
}

async function dbAll(sql, params) {
  const result = await pool.query(sql, params);
  return result.rows;
}

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRE,
  });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function generateTOTPSecret(username, email) {
  return speakeasy.generateSecret({
    name: `TAHAMUZZA (${email})`,
    issuer: "TAHAMUZZA",
    length: 32,
  });
}

function verifyTOTPToken(secret, token) {
  return speakeasy.totp.verify({ secret, encoding: "base32", token, window: 2 });
}

function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    codes.push(Math.random().toString(36).substring(2, 10).toUpperCase());
  }
  return codes;
}

function authenticateToken(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token no proporcionado" });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ message: "Token inválido o expirado" });

  req.user = decoded;
  next();
}

// ===== RUTAS =====
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", service: "TAHAMUZZA Backend activo", time: new Date().toISOString() });
});

// ===== INICIALIZAR Y ARRANCAR SERVIDOR =====
app.listen(PORT, () => {
  console.log(`🚀 Servidor iniciado en puerto ${PORT}`);
  // Iniciar la conexión a la base de datos sin bloquear el arranque
  initializeDatabase().catch((err) => {
    console.error("❌ Error al inicializar la base de datos:", err);
  });
});

