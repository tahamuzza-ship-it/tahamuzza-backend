/**
 * TAHAMUZZA - Backend Express con 2FA y JWT
 * Portal seguro de acceso restringido con autenticación de dos factores
 * 
 * Características:
 * - Autenticación con JWT + Cookies HTTP-only
 * - 2FA TOTP con Speakeasy
 * - Bcryptjs para hash de contraseñas
 * - SQLite para persistencia
 * - CORS habilitado
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const path = require('path');

// ===== CONFIGURACIÓN =====
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta_cambiar_en_produccion';
const JWT_EXPIRE = '7d';
const DB_PATH = path.join(__dirname, 'tahamuzza.db');

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.static(__dirname));
app.use(cookieParser());
app.use(cors({
    origin: '*',
    credentials: true
}));

// ===== BASE DE DATOS =====
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('[DB] Error conectando:', err);
    } else {
        console.log('[DB] Conectado a SQLite');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        // Tabla de usuarios
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT,
                role TEXT DEFAULT 'user',
                twoFASecret TEXT,
                twoFAEnabled INTEGER DEFAULT 0,
                twoFABackupCodes TEXT,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Tabla de sesiones 2FA
        db.run(`
            CREATE TABLE IF NOT EXISTS twofa_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER NOT NULL,
                sessionToken TEXT UNIQUE NOT NULL,
                expiresAt DATETIME NOT NULL,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id)
            )
        `);

        console.log('[DB] Tablas inicializadas');
    });
}

// ===== UTILIDADES =====

/**
 * Generar token JWT
 */
function generateToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRE }
    );
}

/**
 * Verificar token JWT
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

/**
 * Generar código TOTP
 */
function generateTOTPSecret(username, email) {
    return speakeasy.generateSecret({
        name: `TAHAMUZZA (${email})`,
        issuer: 'TAHAMUZZA',
        length: 32
    });
}

/**
 * Verificar código TOTP
 */
function verifyTOTPToken(secret, token) {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 2
    });
}

/**
 * Generar códigos de respaldo
 */
function generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const code = Math.random().toString(36).substring(2, 10).toUpperCase();
        codes.push(code);
    }
    return codes;
}

/**
 * Middleware de autenticación
 */
function authenticateToken(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token no proporcionado' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ message: 'Token inválido o expirado' });
    }

    req.user = decoded;
    next();
}

/**
 * Obtener usuario por ID
 */
function getUserById(id, callback) {
    db.get(
        'SELECT id, username, email, name, role, twoFAEnabled FROM users WHERE id = ?',
        [id],
        callback
    );
}

/**
 * Obtener usuario por username
 */
function getUserByUsername(username, callback) {
    db.get(
        'SELECT * FROM users WHERE username = ?',
        [username],
        callback
    );
}

// ===== RUTAS DE AUTENTICACIÓN =====

/**
 * POST /api/auth/register
 * Registrar nuevo usuario
 */
app.post('/api/auth/register', (req, res) => {
    const { username, email, password, name } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Campos requeridos faltantes' });
    }

    // Hash de contraseña
    const hashedPassword = bcryptjs.hashSync(password, 10);

    db.run(
        'INSERT INTO users (username, email, password, name, role) VALUES (?, ?, ?, ?, ?)',
        [username, email, hashedPassword, name || username, 'user'],
        function(err) {
            if (err) {
                return res.status(400).json({ message: 'Usuario ya existe' });
            }

            const user = {
                id: this.lastID,
                username,
                email,
                name: name || username,
                role: 'user'
            };

            const token = generateToken(user);
            res.cookie('token', token, {
                httpOnly: true,
                secure: false, // Cambiar a true en producción con HTTPS
                sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 días
            });

            res.json({
                message: 'Usuario registrado exitosamente',
                token,
                user
            });
        }
    );
});

/**
 * POST /api/auth/login
 * Login con validación de contraseña
 */
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña requeridos' });
    }

    getUserByUsername(username, (err, user) => {
        if (err || !user) {
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }

        // Verificar contraseña
        const passwordValid = bcryptjs.compareSync(password, user.password);
        if (!passwordValid) {
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }

        // Si 2FA está habilitado, crear sesión temporal
        if (user.twoFAEnabled) {
            const sessionToken = jwt.sign(
                { userId: user.id },
                JWT_SECRET,
                { expiresIn: '5m' }
            );

            // Guardar sesión en BD
            db.run(
                'INSERT INTO twofa_sessions (userId, sessionToken, expiresAt) VALUES (?, ?, datetime(\'now\', \'+5 minutes\'))',
                [user.id, sessionToken],
                (err) => {
                    if (err) {
                        return res.status(500).json({ message: 'Error creando sesión' });
                    }

                    res.json({
                        message: 'Se requiere verificación 2FA',
                        requiresTwoFA: true,
                        sessionToken
                    });
                }
            );
        } else {
            // Login exitoso sin 2FA
            const token = generateToken(user);
            res.cookie('token', token, {
                httpOnly: true,
                secure: false,
                sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            res.json({
                message: 'Login exitoso',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    twoFAEnabled: user.twoFAEnabled
                }
            });
        }
    });
});

/**
 * POST /api/auth/verify-2fa
 * Verificar código 2FA
 */
app.post('/api/auth/verify-2fa', (req, res) => {
    const { sessionToken, token } = req.body;

    if (!sessionToken || !token) {
        return res.status(400).json({ message: 'SessionToken y código requeridos' });
    }

    // Verificar sesión temporal
    const decoded = verifyToken(sessionToken);
    if (!decoded) {
        return res.status(401).json({ message: 'Sesión expirada' });
    }

    const userId = decoded.userId;

    // Obtener usuario
    getUserById(userId, (err, user) => {
        if (err || !user) {
            return res.status(401).json({ message: 'Usuario no encontrado' });
        }

        // Verificar código TOTP
        const isValid = verifyTOTPToken(user.twoFASecret, token);

        if (!isValid) {
            // Verificar códigos de respaldo
            const backupCodes = JSON.parse(user.twoFABackupCodes || '[]');
            const backupCodeIndex = backupCodes.indexOf(token);

            if (backupCodeIndex === -1) {
                return res.status(401).json({ message: 'Código 2FA inválido' });
            }

            // Usar código de respaldo
            backupCodes.splice(backupCodeIndex, 1);
            db.run(
                'UPDATE users SET twoFABackupCodes = ? WHERE id = ?',
                [JSON.stringify(backupCodes), userId]
            );
        }

        // Eliminar sesión 2FA
        db.run('DELETE FROM twofa_sessions WHERE sessionToken = ?', [sessionToken]);

        // Generar token JWT
        const jwtToken = generateToken(user);
        res.cookie('token', jwtToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({
            message: '2FA verificado exitosamente',
            token: jwtToken,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                twoFAEnabled: user.twoFAEnabled
            }
        });
    });
});

/**
 * POST /api/auth/setup-2fa
 * Generar código QR y secreto para 2FA
 */
app.post('/api/auth/setup-2fa', authenticateToken, (req, res) => {
    getUserById(req.user.id, async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        // Generar secreto TOTP
        const secret = generateTOTPSecret(user.username, user.email);
        const backupCodes = generateBackupCodes();

        // Generar código QR
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        res.json({
            message: 'Secreto 2FA generado',
            secret: secret.base32,
            qrCode,
            backupCodes
        });
    });
});

/**
 * POST /api/auth/confirm-2fa
 * Confirmar y guardar 2FA
 */
app.post('/api/auth/confirm-2fa', authenticateToken, (req, res) => {
    const { token, secret, backupCodes } = req.body;

    if (!token || !secret || !backupCodes) {
        return res.status(400).json({ message: 'Datos incompletos' });
    }

    // Verificar código TOTP
    const isValid = verifyTOTPToken(secret, token);
    if (!isValid) {
        return res.status(401).json({ message: 'Código 2FA inválido' });
    }

    // Guardar en BD
    db.run(
        'UPDATE users SET twoFASecret = ?, twoFAEnabled = 1, twoFABackupCodes = ? WHERE id = ?',
        [secret, JSON.stringify(backupCodes), req.user.id],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error guardando 2FA' });
            }

            res.json({ message: '2FA habilitado exitosamente' });
        }
    );
});

/**
 * GET /api/auth/me
 * Obtener usuario actual
 */
app.get('/api/auth/me', authenticateToken, (req, res) => {
    getUserById(req.user.id, (err, user) => {
        if (err || !user) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            name: user.name,
            role: user.role,
            twoFAEnabled: user.twoFAEnabled
        });
    });
});

/**
 * POST /api/auth/logout
 * Logout
 */
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout exitoso' });
});

// ===== RUTAS DE USUARIOS =====

/**
 * GET /api/users
 * Listar todos los usuarios (solo admin)
 */
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado' });
    }

    db.all(
        'SELECT id, username, email, name, role, twoFAEnabled, createdAt FROM users',
        (err, users) => {
            if (err) {
                return res.status(500).json({ message: 'Error obteniendo usuarios' });
            }

            res.json(users);
        }
    );
});

/**
 * GET /api/users/:id
 * Obtener usuario por ID (solo admin)
 */
app.get('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado' });
    }

    getUserById(req.params.id, (err, user) => {
        if (err || !user) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            name: user.name,
            role: user.role,
            twoFAEnabled: user.twoFAEnabled
        });
    });
});

// ===== RUTAS ESTÁTICAS =====

/**
 * GET /
 * Servir index.html
 */
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

/**
 * GET /publish.html
 * Servir página de publicación
 */
app.get('/publish.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'publish.html'));
});

// ===== MANEJO DE ERRORES =====

app.use((err, req, res, next) => {
    console.error('[ERROR]', err);
    res.status(500).json({ message: 'Error interno del servidor' });
});

// ===== INICIAR SERVIDOR =====

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║                   TAHAMUZZA BACKEND                        ║
║           Portal Seguro con 2FA - Express.js              ║
╚════════════════════════════════════════════════════════════╝

🚀 Servidor corriendo en: http://localhost:${PORT}
🔐 Seguridad: JWT + 2FA TOTP + Bcryptjs
📊 Base de datos: SQLite (${DB_PATH})
🌐 CORS: Habilitado
🔑 JWT Secret: ${JWT_SECRET === 'tu_clave_secreta_cambiar_en_produccion' ? '⚠️  CAMBIAR EN PRODUCCIÓN' : '✓ Configurado'}

📝 Credenciales de prueba:
   Usuario: admin
   Contraseña: admin123

🔗 Endpoints disponibles:
   POST   /api/auth/register      - Registrar usuario
   POST   /api/auth/login         - Login
   POST   /api/auth/verify-2fa    - Verificar 2FA
   POST   /api/auth/setup-2fa     - Setup 2FA
   POST   /api/auth/confirm-2fa   - Confirmar 2FA
   GET    /api/auth/me            - Usuario actual
   POST   /api/auth/logout        - Logout
   GET    /api/users              - Listar usuarios (admin)
   GET    /api/users/:id          - Obtener usuario (admin)

📖 Documentación: http://localhost:${PORT}/publish.html
    `);
});

// ===== GRACEFUL SHUTDOWN =====

process.on('SIGINT', () => {
    console.log('\n[SERVER] Cerrando servidor...');
    db.close((err) => {
        if (err) console.error('[DB] Error cerrando:', err);
        process.exit(0);
    });
});
