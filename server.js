corrigeme este codigo que me dio error de sintaxis al conectar, para conectar con raylway , 
pasted_content.txt
Texto · 11.17 KB

Voy a analizar el código adjunto para detectar errores de sintaxis y poder corregirlos en la siguiente fase.

El código actual usa SQLite, pero para Railway con PostgreSQL, debo reemplazar la conexión por una que utilice la variable de entorno DATABASE_URL y el cliente de PostgreSQL.
damelo .jv
Lite
Entendido. El código que me proporcionaste está escrito en JavaScript (Node.js/Express) y utiliza SQLite como base de datos.
Mencionaste que el error de sintaxis ocurre al conectar con Railway. Railway es una plataforma de despliegue que a menudo utiliza PostgreSQL para bases de datos, y proporciona la cadena de conexión a través de la variable de entorno DATABASE_URL.
El código actual usa sqlite3 (línea 19) y un archivo local (tahamuzza.db en la línea 28), lo cual no es adecuado para un entorno de Railway que requiere una base de datos persistente como PostgreSQL.
El error de sintaxis que experimentaste probablemente se debe a que intentaste usar la variable de entorno DATABASE_URL de Railway con el cliente sqlite3, o que el código no está preparado para usar PostgreSQL.
Para corregir esto y hacerlo compatible con Railway, necesito hacer los siguientes cambios:

    Cambiar el cliente de base de datos: Reemplazar sqlite3 por un cliente de PostgreSQL, como pg o pg-promise.
    Usar la variable de entorno DATABASE_URL: Configurar la conexión para que use process.env.DATABASE_URL.

Voy a reescribir la sección de la base de datos para usar PostgreSQL con el paquete pg y la variable de entorno DATABASE_URL.
¿Estás de acuerdo con que reescriba la conexión para usar PostgreSQL (que es lo común en Railway) en lugar de SQLite?
Si me confirmas, procederé con la corrección. Si prefieres seguir usando SQLite, te informo que SQLite no es una opción de base de datos persistente recomendada para entornos de producción como Railway, ya que el archivo de base de datos se perdería con cada reinicio del contenedor.
Por favor, confírmame si quieres la corrección para PostgreSQL.
si me funciona en raylway si
Lite
Perfecto. Procederé a modificar el código para que utilice PostgreSQL y la variable de entorno DATABASE_URL, lo cual es la configuración estándar y recomendada para Railway.
Esto implica:

    Instalar el paquete pg.
    Reemplazar las llamadas a sqlite3 por el cliente pg.
    Ajustar las consultas SQL para la sintaxis de PostgreSQL (aunque en este caso las consultas son bastante estándar).

Comenzaré con la fase de modificación del código. Te entregaré el resultado en breve.

Voy a reemplazar la conexión SQLite por PostgreSQL usando la variable `DATABASE_URL` y el cliente `pg`, confirmando que la configuración ahora sea compatible con Railway.

He identificado que el código tiene un error de sintaxis o configuración para conectar a Railway. Voy a corregirlo usando la variable de entorno `DATABASE_URL` y el cliente de PostgreSQL.
Lite
Aquí tienes el código corregido y adaptado para funcionar correctamente en Railway utilizando PostgreSQL a través de la variable de entorno DATABASE_URL.
He realizado los siguientes cambios clave:

    Reemplazo de sqlite3 por pg (PostgreSQL): Se utiliza el paquete pg y su Pool de conexiones.
    Uso de DATABASE_URL: La conexión se configura automáticamente para usar la variable de entorno DATABASE_URL proporcionada por Railway.
    Sintaxis de PostgreSQL: Las consultas SQL se han adaptado para usar la sintaxis de PostgreSQL (por ejemplo, SERIAL PRIMARY KEY, TIMESTAMP WITH TIME ZONE, y RETURNING id para obtener el ID de inserción).
    Uso de async/await: Se han refactorizado las funciones de base de datos para usar async/await y manejar las promesas del cliente pg, lo que resulta en un código más limpio y moderno.

Pasos para usar este código en Railway:

    Guarda el archivo como index.js (o el nombre que uses para tu archivo principal).
    Instala las dependencias necesarias:
    Bash

    npm install express cors jsonwebtoken bcryptjs speakeasy qrcode cookie-parser pg

    Asegúrate de que tu proyecto en Railway tenga un servicio de PostgreSQL conectado. Railway configurará automáticamente la variable de entorno DATABASE_URL con la cadena de conexión correcta.
    Despliega tu código en Railway.

El código adjunto (tahamuzza_corrected.js) es la versión final. Si tienes alguna otra pregunta o necesitas más ajustes, no dudes en consultarme.
tahamuzza_corrected.js
Código · 14.86 KB
Tarea completada
¿Cómo fue este resultado?
Seguimientos sugeridos
tahamuzza_corrected.js

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

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const cookieParser = require('cookie-parser');
const path = require('path');
// ** CAMBIO CLAVE: Usar el cliente de PostgreSQL 'pg' **
const { Pool } = require('pg');

// ===== CONFIGURACIÓN =====
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta_cambiar_en_produccion';
const JWT_EXPIRE = '7d';
// ** CAMBIO CLAVE: Usar DATABASE_URL de Railway **
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error('FATAL: La variable de entorno DATABASE_URL no está configurada. Necesaria para Railway.');
    process.exit(1);
}

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.static(__dirname));
app.use(cookieParser());
app.use(cors({
    origin: '*',
    credentials: true
}));

// ===== BASE DE DATOS (PostgreSQL) =====
// Configuración del pool de conexiones
const pool = new Pool({
    connectionString: DATABASE_URL,
    // Configuración SSL necesaria para muchos proveedores de hosting, incluido Railway
    ssl: {
        rejectUnauthorized: false
    }
});

// Función para inicializar la base de datos
async function initializeDatabase() {
    try {
        // Conexión de prueba
        await pool.query('SELECT 1');
        console.log('[DB] Conectado a PostgreSQL');

        // Creación de la tabla users (usando SERIAL para auto-incremento en PG)
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

        // Creación de la tabla twofa_sessions
        await pool.query(`
            CREATE TABLE IF NOT EXISTS twofa_sessions (
                id SERIAL PRIMARY KEY,
                "userId" INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "sessionToken" TEXT UNIQUE NOT NULL,
                "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL,
                "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('[DB] Tablas inicializadas');
    } catch (err) {
        console.error('[DB] Error al conectar o inicializar la base de datos:', err);
        // Terminar el proceso si la conexión a la DB falla
        process.exit(1);
    }
}

// Iniciar la conexión e inicialización de la DB
initializeDatabase();

// ===== UTILIDADES (Adaptadas para usar el pool de PG) =====

// Función genérica para ejecutar una consulta SELECT y devolver un único resultado
async function dbGet(sql, params) {
    const result = await pool.query(sql, params);
    return result.rows[0];
}

// Función genérica para ejecutar una consulta INSERT/UPDATE/DELETE
async function dbRun(sql, params) {
    const result = await pool.query(sql, params);
    // Para INSERT, devolvemos el ID si la tabla tiene SERIAL PRIMARY KEY
    if (sql.trim().toUpperCase().startsWith('INSERT') && result.rows.length > 0) {
        return result.rows[0].id;
    }
    return result.rowCount;
}

// Función genérica para ejecutar una consulta SELECT y devolver múltiples resultados
async function dbAll(sql, params) {
    const result = await pool.query(sql, params);
    return result.rows;
}

function generateToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRE }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function generateTOTPSecret(username, email) {
    return speakeasy.generateSecret({
        name: `TAHAMUZZA (${email})`,
        issuer: 'TAHAMUZZA',
        length: 32
    });
}

function verifyTOTPToken(secret, token) {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 2
    });
}

function generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const code = Math.random().toString(36).substring(2, 10).toUpperCase();
        codes.push(code);
    }
    return codes;
}

function authenticateToken(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token no proporcionado' });

    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ message: 'Token inválido o expirado' });

    req.user = decoded;
    next();
}

// Adaptación de las funciones de usuario a async/await con dbGet
async function getUserById(id) {
    return dbGet(
        'SELECT id, username, email, name, role, "twoFAEnabled", "twoFASecret", "twoFABackupCodes" FROM users WHERE id = $1',
        [id]
    );
}

async function getUserByUsername(username) {
    return dbGet(
        'SELECT * FROM users WHERE username = $1',
        [username]
    );
}

// ===== RUTAS DE AUTENTICACIÓN (Adaptadas a async/await) =====
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, name } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Campos requeridos faltantes' });
    }

    const hashedPassword = bcryptjs.hashSync(password, 10);

    try {
        // Usamos RETURNING id para obtener el ID del nuevo usuario (necesario para generateToken)
        const sql = 'INSERT INTO users (username, email, password, name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id';
        const result = await pool.query(sql, [username, email, hashedPassword, name || username, 'user']);
        const newUserId = result.rows[0].id;

        const user = { id: newUserId, username, email, name: name || username, role: 'user' };
        const token = generateToken(user);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Usar secure en producción
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ message: 'Usuario registrado exitosamente', token, user });
    } catch (err) {
        // Error 23505 es el código de error de unicidad en PostgreSQL
        if (err.code === '23505') {
            return res.status(400).json({ message: 'Usuario o email ya existe' });
        }
        console.error('Error en registro:', err);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Usuario y contraseña requeridos' });

    try {
        const user = await getUserByUsername(username);

        if (!user) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });

        const passwordValid = bcryptjs.compareSync(password, user.password);
        if (!passwordValid) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });

        if (user.twoFAEnabled) {
            const sessionToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '5m' });
            
            // Usamos NOW() + INTERVAL '5 minutes' para PostgreSQL
            const sql = 'INSERT INTO twofa_sessions ("userId", "sessionToken", "expiresAt") VALUES ($1, $2, NOW() + INTERVAL \'5 minutes\')';
            await pool.query(sql, [user.id, sessionToken]);

            res.json({ message: 'Se requiere verificación 2FA', requiresTwoFA: true, sessionToken });
        } else {
            const token = generateToken(user);
            res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
            res.json({ message: 'Login exitoso', token, user });
        }
    } catch (err) {
        console.error('Error en login:', err);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

app.post('/api/auth/verify-2fa', async (req, res) => {
    const { sessionToken, token } = req.body;
    if (!sessionToken || !token) return res.status(400).json({ message: 'SessionToken y código requeridos' });

    const decoded = verifyToken(sessionToken);
    if (!decoded) return res.status(401).json({ message: 'Sesión expirada' });

    const userId = decoded.userId;

    try {
        const user = await getUserById(userId);
        if (!user) return res.status(401).json({ message: 'Usuario no encontrado' });

        let isValid = false;
        if (user.twoFASecret) {
            isValid = verifyTOTPToken(user.twoFASecret, token);
        }

        if (!isValid) {
            const backupCodes = JSON.parse(user.twoFABackupCodes || '[]');
            const index = backupCodes.indexOf(token);
            if (index !== -1) {
                // Código de respaldo válido
                backupCodes.splice(index, 1);
                await pool.query('UPDATE users SET "twoFABackupCodes" = $1 WHERE id = $2', [JSON.stringify(backupCodes), userId]);
                isValid = true;
            }
        }

        if (!isValid) {
            return res.status(401).json({ message: 'Código 2FA inválido' });
        }

        // Eliminar la sesión 2FA
        await pool.query('DELETE FROM twofa_sessions WHERE "sessionToken" = $1', [sessionToken]);
        
        const jwtToken = generateToken(user);
        res.cookie('token', jwtToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ message: '2FA verificado exitosamente', token: jwtToken, user });
    } catch (err) {
        console.error('Error en verificación 2FA:', err);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

app.post('/api/auth/setup-2fa', authenticateToken, async (req, res) => {
    try {
        const user = await getUserById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

        const secret = generateTOTPSecret(user.username, user.email);
        const backupCodes = generateBackupCodes();
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        res.json({ message: 'Secreto 2FA generado', secret: secret.base32, qrCode, backupCodes });
    } catch (err) {
        console.error('Error en setup 2FA:', err);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

app.post('/api/auth/confirm-2fa', authenticateToken, async (req, res) => {
    const { token, secret, backupCodes } = req.body;
    if (!token || !secret || !backupCodes) return res.status(400).json({ message: 'Datos incompletos' });

    const isValid = verifyTOTPToken(secret, token);
    if (!isValid) return res.status(401).json({ message: 'Código 2FA inválido' });

    try {
        const sql = 'UPDATE users SET "twoFASecret" = $1, "twoFAEnabled" = TRUE, "twoFABackupCodes" = $2 WHERE id = $3';
        await pool.query(sql, [secret, JSON.stringify(backupCodes), req.user.id]);
        
        res.json({ message: '2FA habilitado exitosamente' });
    } catch (err) {
        console.error('Error en confirmación 2FA:', err);
        return res.status(500).json({ message: 'Error guardando 2FA' });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await getUserById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
        res.json(user);
    } catch (err) {
        console.error('Error en /me:', err);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout exitoso' });
});

// ===== RUTAS DE USUARIOS (Adaptadas a async/await) =====
app.get('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    try {
        const users = await dbAll('SELECT id, username, email, name, role, "twoFAEnabled", "createdAt" FROM users');
        res.json(users);
    } catch (err) {
        console.error('Error obteniendo usuarios:', err);
        return res.status(500).json({ message: 'Error obteniendo usuarios' });
    }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    try {
        const user = await getUserById(req.params.id);
        if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
        res.json(user);
    } catch (err) {
        console.error('Error obteniendo usuario por ID:', err);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// ===== RUTAS ESTÁTICAS =====
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/publish.html', (req, res) => res.sendFile(path.join(__dirname, 'publish.html')));

// ===== NUEVA RUTA DE PRUEBA =====
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'TAHAMUZZA Backend activo',
        time: new Date().toISOString()
    });
});

// ===== MANEJO DE ERRORES =====
app.use((err, req, res, next) => {
    console.error('[ERROR]', err);
    res.status(500).json({ message: 'Error interno del servidor' });
});

// ===== INICIAR SERVIDOR =====
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en: http://localhost:${PORT}`);
    console.log(`🔑 JWT Secret: ${JWT_SECRET === 'tu_clave_secreta_cambiar_en_produccion' ? '⚠️ CAMBIAR EN PRODUCCIÓN' : '✓ Configurado'}`);
});

// ===== GRACEFUL SHUTDOWN =====
process.on('SIGINT', async () => {
    console.log('\n[SERVER] Cerrando servidor...');
    try {
        await pool.end(); // Cerrar todas las conexiones del pool
        console.log('[DB] Conexiones a PostgreSQL cerradas.');
        process.exit(0);
    } catch (err) {
        console.error('[DB] Error cerrando conexiones:', err);
        process.exit(1);
    }
});

Manus