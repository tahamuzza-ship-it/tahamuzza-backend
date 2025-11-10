/**
 * TAHAMUZZA - Backend Express con 2FA y JWT
 * Portal seguro de acceso restringido con autenticación de dos factores
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

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // necesario para webhook Make
app.use(cookieParser());
app.use(cors({ origin: "*", credentials: true }));
app.use(express.static(path.resolve("public")));

// ===== BASE DE DATOS (PostgreSQL) =====
if (!DATABASE_URL) {
  console.error("❌ FATAL: La variable DATABASE_URL no está configurada.");
  process.exit(1);
}

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
  }
}

// ===== UTILIDADES =====
async function dbGet(sql, params) {
  const result = await pool.query(sql, params);
  return result.rows[0];
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

// ===== RUTAS DE AUTENTICACIÓN Y 2FA =====

// REGISTRO
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: "Faltan datos" });

  const hash = await bcryptjs.hash(password, 10);
  try {
    const user = await dbGet(
      `INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, role`,
      [username, email, hash]
    );
    res.json({ message: "Usuario creado ✅", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error al registrar usuario" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Faltan datos" });

  const user = await dbGet("SELECT * FROM users WHERE email=$1", [email]);
  if (!user) return res.status(401).json({ message: "Usuario no encontrado" });

  const valid = await bcryptjs.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Contraseña incorrecta" });

  const token = generateToken(user);
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.json({ message: "Login correcto ✅", token });
});

// ACTIVAR 2FA
app.post("/api/enable-2fa", authenticateToken, async (req, res) => {
  const user = req.user;
  const secret = generateTOTPSecret(user.username, user.email);
  const qr = await QRCode.toDataURL(secret.otpauth_url);

  await pool.query(`UPDATE users SET "twoFASecret"=$1, "twoFAEnabled"=TRUE WHERE id=$2`, [
    secret.base32,
    user.id,
  ]);

  res.json({ message: "2FA habilitado ✅", secret: secret.base32, qr });
});

// VERIFICAR 2FA
app.post("/api/verify-2fa", authenticateToken, async (req, res) => {
  const { token } = req.body;
  const user = await dbGet("SELECT * FROM users WHERE id=$1", [req.user.id]);

  if (!user || !user.twoFASecret)
    return res.status(400).json({ message: "2FA no habilitado" });

  const verified = verifyTOTPToken(user.twoFASecret, token);
  if (!verified) return res.status(401).json({ message: "Código inválido" });

  res.json({ message: "2FA verificado correctamente ✅" });
});

// ===== WEBHOOK MAKE =====
app.post("/api/webhook/make", (req, res) => {
  console.log("📩 Webhook recibido de Make:", req.body);
  res.json({ received: true, timestamp: new Date().toISOString() });
});

// ===== INICIALIZAR Y ARRANCAR SERVIDOR =====
app.listen(PORT, () => {
  console.log(`🚀 Servidor iniciado en puerto ${PORT}`);
  initializeDatabase().catch((err) => {
    console.error("❌ Error al inicializar la base de datos:", err);
  });
});
