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

function getUserById(id, callback) {
    db.get(
        'SELECT id, username, email, name, role, twoFAEnabled FROM users WHERE id = ?',
        [id],
        callback
    );
}

function getUserByUsername(username, callback) {
    db.get(
        'SELECT * FROM users WHERE username = ?',
        [username],
        callback
    );
}

// ===== RUTAS DE AUTENTICACIÓN =====
app.post('/api/auth/register', (req, res) => {
    const { username, email, password, name } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Campos requeridos faltantes' });
    }

    const hashedPassword = bcryptjs.hashSync(password, 10);

    db.run(
        'INSERT INTO users (username, email, password, name, role) VALUES (?, ?, ?, ?, ?)',
        [username, email, hashedPassword, name || username, 'user'],
        function (err) {
            if (err) return res.status(400).json({ message: 'Usuario ya existe' });

            const user = { id: this.lastID, username, email, name: name || username, role: 'user' };
            const token = generateToken(user);

            res.cookie('token', token, {
                httpOnly: true,
                secure: false,
                sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            res.json({ message: 'Usuario registrado exitosamente', token, user });
        }
    );
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Usuario y contraseña requeridos' });

    getUserByUsername(username, (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });

        const passwordValid = bcryptjs.compareSync(password, user.password);
        if (!passwordValid) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });

        if (user.twoFAEnabled) {
            const sessionToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '5m' });
            db.run(
                'INSERT INTO twofa_sessions (userId, sessionToken, expiresAt) VALUES (?, ?, datetime(\'now\', \'+5 minutes\'))',
                [user.id, sessionToken],
                (err) => {
                    if (err) return res.status(500).json({ message: 'Error creando sesión' });
                    res.json({ message: 'Se requiere verificación 2FA', requiresTwoFA: true, sessionToken });
                }
            );
        } else {
            const token = generateToken(user);
            res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
            res.json({ message: 'Login exitoso', token, user });
        }
    });
});

app.post('/api/auth/verify-2fa', (req, res) => {
    const { sessionToken, token } = req.body;
    if (!sessionToken || !token) return res.status(400).json({ message: 'SessionToken y código requeridos' });

    const decoded = verifyToken(sessionToken);
    if (!decoded) return res.status(401).json({ message: 'Sesión expirada' });

    const userId = decoded.userId;
    getUserById(userId, (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Usuario no encontrado' });

        const isValid = verifyTOTPToken(user.twoFASecret, token);
        if (!isValid) {
            const backupCodes = JSON.parse(user.twoFABackupCodes || '[]');
            const index = backupCodes.indexOf(token);
            if (index === -1) return res.status(401).json({ message: 'Código 2FA inválido' });
            backupCodes.splice(index, 1);
            db.run('UPDATE users SET twoFABackupCodes = ? WHERE id = ?', [JSON.stringify(backupCodes), userId]);
        }

        db.run('DELETE FROM twofa_sessions WHERE sessionToken = ?', [sessionToken]);
        const jwtToken = generateToken(user);
        res.cookie('token', jwtToken, { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ message: '2FA verificado exitosamente', token: jwtToken, user });
    });
});

app.post('/api/auth/setup-2fa', authenticateToken, (req, res) => {
    getUserById(req.user.id, async (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'Usuario no encontrado' });

        const secret = generateTOTPSecret(user.username, user.email);
        const backupCodes = generateBackupCodes();
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        res.json({ message: 'Secreto 2FA generado', secret: secret.base32, qrCode, backupCodes });
    });
});

app.post('/api/auth/confirm-2fa', authenticateToken, (req, res) => {
    const { token, secret, backupCodes } = req.body;
    if (!token || !secret || !backupCodes) return res.status(400).json({ message: 'Datos incompletos' });

    const isValid = verifyTOTPToken(secret, token);
    if (!isValid) return res.status(401).json({ message: 'Código 2FA inválido' });

    db.run(
        'UPDATE users SET twoFASecret = ?, twoFAEnabled = 1, twoFABackupCodes = ? WHERE id = ?',
        [secret, JSON.stringify(backupCodes), req.user.id],
        (err) => {
            if (err) return res.status(500).json({ message: 'Error guardando 2FA' });
            res.json({ message: '2FA habilitado exitosamente' });
        }
    );
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    getUserById(req.user.id, (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'Usuario no encontrado' });
        res.json(user);
    });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout exitoso' });
});

// ===== RUTAS DE USUARIOS =====
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    db.all('SELECT id, username, email, name, role, twoFAEnabled, createdAt FROM users', (err, users) => {
        if (err) return res.status(500).json({ message: 'Error obteniendo usuarios' });
        res.json(users);
    });
});

app.get('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    getUserById(req.params.id, (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'Usuario no encontrado' });
        res.json(user);
    });
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
process.on('SIGINT', () => {
    console.log('\n[SERVER] Cerrando servidor...');
    db.close((err) => {
        if (err) console.error('[DB] Error cerrando:', err);
        process.exit(0);
    });
});

    
  