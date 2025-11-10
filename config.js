/**
 * TAHAMUZZA - Configuración Global
 * Variables de entorno y configuración de seguridad
 */

module.exports = {
    // ===== SERVIDOR =====
    PORT: process.env.PORT || 3000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    HOST: process.env.HOST || 'localhost',

    // ===== AUTENTICACIÓN JWT =====
    JWT_SECRET: process.env.JWT_SECRET || 'tu_clave_secreta_super_segura_cambiar_en_produccion_2024',
    JWT_EXPIRE: process.env.JWT_EXPIRE || '7d',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'refresh_secret_cambiar_en_produccion',
    JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE || '30d',

    // ===== BASE DE DATOS =====
    DATABASE_URL: process.env.DATABASE_URL || 'sqlite:./tahamuzza.db',
    DB_PATH: process.env.DB_PATH || './tahamuzza.db',

    // ===== WEBHOOK MAKE.COM =====
    WEBHOOK_URL: process.env.WEBHOOK_URL || 'https://hook.us2.make.com/usfyxbrd302u2per86a9j06wnmsahyej',
    WEBHOOK_ENABLED: process.env.WEBHOOK_ENABLED !== 'false',

    // ===== SEGURIDAD =====
    BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '10'),
    SESSION_TIMEOUT: parseInt(process.env.SESSION_TIMEOUT || '3600000'), // 1 hora en ms
    TWO_FA_TIMEOUT: parseInt(process.env.TWO_FA_TIMEOUT || '300000'), // 5 minutos en ms
    MAX_LOGIN_ATTEMPTS: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
    LOCK_TIME: parseInt(process.env.LOCK_TIME || '900000'), // 15 minutos en ms

    // ===== CORS =====
    CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
    CORS_CREDENTIALS: process.env.CORS_CREDENTIALS !== 'false',

    // ===== COOKIES =====
    COOKIE_SECURE: process.env.COOKIE_SECURE === 'true',
    COOKIE_HTTP_ONLY: process.env.COOKIE_HTTP_ONLY !== 'false',
    COOKIE_SAME_SITE: process.env.COOKIE_SAME_SITE || 'lax',
    COOKIE_MAX_AGE: parseInt(process.env.COOKIE_MAX_AGE || '604800000'), // 7 días en ms

    // ===== LOGGING =====
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',
    LOG_FILE: process.env.LOG_FILE || './logs/app.log',

    // ===== FEATURES =====
    ENABLE_2FA: process.env.ENABLE_2FA !== 'false',
    ENABLE_REGISTRATION: process.env.ENABLE_REGISTRATION === 'true',
    ENABLE_WEBHOOK_LOGS: process.env.ENABLE_WEBHOOK_LOGS !== 'false',

    // ===== EMAIL (Opcional) =====
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_PORT: parseInt(process.env.SMTP_PORT || '587'),
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    SMTP_FROM: process.env.SMTP_FROM || 'noreply@tahamuzza.local',

    // ===== INFORMACIÓN DEL PORTAL =====
    APP_NAME: 'TAHAMUZZA',
    APP_VERSION: '1.0.0',
    APP_DESCRIPTION: 'Portal Seguro de Acceso Restringido con 2FA',
    APP_LOGO: '/assets/logo.svg',
    APP_FAVICON: '/assets/favicon.ico',

    // ===== VALIDACIÓN =====
    USERNAME_MIN_LENGTH: 3,
    USERNAME_MAX_LENGTH: 20,
    PASSWORD_MIN_LENGTH: 8,
    PASSWORD_REQUIRE_UPPERCASE: true,
    PASSWORD_REQUIRE_NUMBERS: true,
    PASSWORD_REQUIRE_SPECIAL: true,

    // ===== FUNCIONES DE UTILIDAD =====
    isProduction() {
        return this.NODE_ENV === 'production';
    },

    isDevelopment() {
        return this.NODE_ENV === 'development';
    },

    getWebhookUrl() {
        return this.WEBHOOK_URL;
    },

    getJwtSecret() {
        if (this.isProduction() && this.JWT_SECRET.includes('cambiar')) {
            throw new Error('⚠️  JWT_SECRET no ha sido configurado en producción');
        }
        return this.JWT_SECRET;
    },

    getCookieOptions() {
        return {
            httpOnly: this.COOKIE_HTTP_ONLY,
            secure: this.COOKIE_SECURE,
            sameSite: this.COOKIE_SAME_SITE,
            maxAge: this.COOKIE_MAX_AGE
        };
    }
};
