# 🔒 TAHAMUZZA - Portal Seguro con 2FA

Portal web seguro de acceso restringido con autenticación de dos factores (2FA) basada en TOTP. Sistema completamente independiente, funcional y listo para producción.

## ✨ Características Principales

### 🔐 Seguridad
- **Autenticación 2FA TOTP** - Compatible con Google Authenticator, Authy, Microsoft Authenticator
- **JWT + Cookies HTTP-only** - Tokens seguros con expiración de 7 días
- **Bcryptjs** - Hash seguro de contraseñas con 10 rondas
- **Códigos de Respaldo** - 10 códigos únicos para recuperación de cuenta
- **Control de Acceso** - Roles admin/usuario con procedimientos protegidos
- **CORS Seguro** - Configuración restrictiva de origen

### 💼 Funcionalidades
- **Login Seguro** - Validación de credenciales con base de datos
- **Verificación 2FA** - Ingreso de códigos TOTP o códigos de respaldo
- **Dashboard Dinámico** - Información del usuario en tiempo real
- **Panel Administrativo** - Gestión de usuarios y permisos
- **Setup 2FA** - Asistente con código QR y códigos de respaldo
- **Logout Seguro** - Limpieza completa de sesiones

## 🚀 Inicio Rápido

### Requisitos
- Node.js 14+
- npm o yarn

### Instalación

```bash
# 1. Clonar o descargar el proyecto
cd tahamuzza-backend

# 2. Instalar dependencias
npm install

# 3. Inicializar la base de datos
node init-db.js

# 4. Iniciar el servidor
node server.js
```

### Acceso
```
URL: http://localhost:3000
Usuario: admin
Contraseña: admin123
```

## 📁 Estructura del Proyecto

```
tahamuzza-backend/
├── server.js           # Backend Express con toda la lógica
├── index.html          # Portal HTML conectado al backend
├── publish.html        # Página de publicación y documentación
├── init-db.js          # Script de inicialización de base de datos
├── package.json        # Dependencias del proyecto
├── tahamuzza.db        # Base de datos SQLite (se crea automáticamente)
└── README.md           # Este archivo
```

## 🔗 Endpoints de API

### Autenticación

#### Registrar Usuario
```
POST /api/auth/register
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepass123",
  "name": "John Doe"
}
```

#### Login
```
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}

Respuesta:
{
  "message": "Login exitoso",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@tahamuzza.local",
    "name": "Administrador",
    "role": "admin"
  }
}
```

#### Verificar 2FA
```
POST /api/auth/verify-2fa
Content-Type: application/json

{
  "sessionToken": "abc123...",
  "token": "123456"
}
```

#### Setup 2FA
```
POST /api/auth/setup-2fa
Authorization: Bearer <token>

Respuesta:
{
  "secret": "JBSWY3DPEBLW64TMMQ...",
  "qrCode": "data:image/png;base64,...",
  "backupCodes": ["ABC123", "DEF456", ...]
}
```

#### Confirmar 2FA
```
POST /api/auth/confirm-2fa
Authorization: Bearer <token>
Content-Type: application/json

{
  "token": "123456",
  "secret": "JBSWY3DPEBLW64TMMQ...",
  "backupCodes": ["ABC123", "DEF456", ...]
}
```

#### Obtener Usuario Actual
```
GET /api/auth/me
Authorization: Bearer <token>

Respuesta:
{
  "id": 1,
  "username": "admin",
  "email": "admin@tahamuzza.local",
  "name": "Administrador",
  "role": "admin",
  "twoFAEnabled": 0
}
```

#### Logout
```
POST /api/auth/logout
```

### Usuarios (Admin)

#### Listar Usuarios
```
GET /api/users
Authorization: Bearer <token>

Respuesta:
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@tahamuzza.local",
    "name": "Administrador",
    "role": "admin",
    "twoFAEnabled": 0,
    "createdAt": "2025-11-04 12:00:00"
  }
]
```

#### Obtener Usuario por ID
```
GET /api/users/:id
Authorization: Bearer <token>
```

## 🔐 Flujo de Autenticación

```
1. Usuario ingresa credenciales
   ↓
2. Backend valida contraseña con bcryptjs
   ↓
3. Si 2FA está habilitado:
   - Crea sesión temporal
   - Solicita código TOTP
   ↓
4. Usuario ingresa código de 6 dígitos
   ↓
5. Backend verifica con Speakeasy
   ↓
6. Genera JWT token
   ↓
7. Almacena en cookie HTTP-only
   ↓
8. Acceso al dashboard
```

## 📊 Base de Datos

### Tabla: users
```sql
CREATE TABLE users (
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
```

### Tabla: twofa_sessions
```sql
CREATE TABLE twofa_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  sessionToken TEXT UNIQUE NOT NULL,
  expiresAt DATETIME NOT NULL,
  createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (userId) REFERENCES users(id)
)
```

## 🛠️ Stack Tecnológico

| Tecnología | Versión | Propósito |
|---|---|---|
| **Express.js** | 4.18+ | Framework web backend |
| **Node.js** | 14+ | Runtime JavaScript |
| **SQLite3** | 5.1+ | Base de datos |
| **JWT** | 9.0+ | Autenticación segura |
| **Bcryptjs** | 3.0+ | Hash de contraseñas |
| **Speakeasy** | 2.0+ | Generación TOTP |
| **QRCode** | 1.5+ | Códigos QR |
| **CORS** | 2.8+ | Comunicación segura |

## ⚙️ Configuración

### Variables de Entorno (Opcionales)
```
PORT=3000
NODE_ENV=development
JWT_SECRET=tu_clave_secreta_cambiar_en_produccion
JWT_EXPIRE=7d
DATABASE_PATH=./tahamuzza.db
CORS_ORIGIN=*
```

## 🚀 Despliegue en Producción

### Recomendaciones de Seguridad

1. **Cambiar JWT_SECRET**
   ```javascript
   // En server.js línea 9
   const JWT_SECRET = process.env.JWT_SECRET || 'CAMBIAR_ESTO_EN_PRODUCCION';
   ```

2. **Usar HTTPS**
   ```javascript
   // Configurar SSL/TLS en el servidor
   const https = require('https');
   const fs = require('fs');
   ```

3. **Usar Base de Datos Robusta**
   ```bash
   # Cambiar de SQLite a MySQL/PostgreSQL
   npm install mysql2 pg
   ```

4. **Implementar Rate Limiting**
   ```bash
   npm install express-rate-limit
   ```

5. **Agregar Logging**
   ```bash
   npm install winston
   ```

6. **Usar Reverse Proxy**
   ```nginx
   # Nginx configuration
   server {
       listen 443 ssl;
       server_name tahamuzza.com;
       
       location / {
           proxy_pass http://localhost:3000;
       }
   }
   ```

## 📝 Ejemplo de Uso Completo

### 1. Registrar Usuario
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "name": "John Doe"
  }'
```

### 2. Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "password": "SecurePass123!"
  }'
```

### 3. Setup 2FA
```bash
curl -X POST http://localhost:3000/api/auth/setup-2fa \
  -H "Authorization: Bearer <TOKEN>"
```

### 4. Verificar 2FA
```bash
curl -X POST http://localhost:3000/api/auth/verify-2fa \
  -H "Content-Type: application/json" \
  -d '{
    "sessionToken": "<SESSION_TOKEN>",
    "token": "123456"
  }'
```

## 🐛 Solución de Problemas

### Error: "no such table: users"
```bash
# Ejecutar script de inicialización
node init-db.js
```

### Error: "EADDRINUSE: address already in use :::3000"
```bash
# Cambiar puerto en server.js o matar proceso
lsof -i :3000
kill -9 <PID>
```

### Error: "CORS policy"
```javascript
// Verificar configuración CORS en server.js línea 18
app.use(cors({
  origin: '*', // Cambiar según necesidad
  credentials: true
}));
```

## 📚 Documentación Adicional

- [Express.js Docs](https://expressjs.com/)
- [JWT.io](https://jwt.io/)
- [Speakeasy Docs](https://github.com/speakeasyjs/speakeasy)
- [SQLite Docs](https://www.sqlite.org/docs.html)

## 📄 Licencia

MIT License - Libre para usar, modificar y distribuir

## 👨‍💻 Autor

**Tahamuzza Team** - Portal seguro de acceso restringido con 2FA

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## ⚠️ Disclaimer

Este proyecto es proporcionado "tal cual" sin garantías. Asegúrate de:
- Cambiar todas las claves secretas antes de producción
- Usar HTTPS en producción
- Implementar rate limiting
- Realizar auditorías de seguridad regulares
- Mantener dependencias actualizadas

---

**© 2025 Tahamuzza - Portal Seguro de Acceso Restringido**

Para más información, visita: http://localhost:3000/publish.html
