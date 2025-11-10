# 🚀 Guía de Despliegue - TAHAMUZZA en Railway

## Requisitos Previos

- Cuenta en [Railway.app](https://railway.app)
- Repositorio Git (GitHub, GitLab, etc.)
- Proyecto TAHAMUZZA descargado

## Paso 1: Preparar el Repositorio

```bash
# 1. Inicializar Git si no lo has hecho
git init

# 2. Agregar todos los archivos
git add .

# 3. Hacer commit inicial
git commit -m "Initial commit: TAHAMUZZA Secure Portal"

# 4. Crear repositorio en GitHub
# Ir a https://github.com/new y crear nuevo repositorio

# 5. Agregar remote y push
git remote add origin https://github.com/tu-usuario/tahamuzza.git
git branch -M main
git push -u origin main
```

## Paso 2: Conectar Railway

### Opción A: Desde Railway Dashboard

1. Ir a [railway.app/dashboard](https://railway.app/dashboard)
2. Click en "New Project"
3. Seleccionar "Deploy from GitHub"
4. Autorizar Railway en GitHub
5. Seleccionar tu repositorio `tahamuzza`
6. Configurar variables de entorno (ver Paso 3)
7. Click en "Deploy"

### Opción B: Desde CLI

```bash
# 1. Instalar Railway CLI
npm install -g @railway/cli

# 2. Autenticarse
railway login

# 3. Crear proyecto
railway init

# 4. Desplegar
railway up
```

## Paso 3: Configurar Variables de Entorno

En Railway Dashboard, ir a "Variables" y agregar:

| Variable | Valor | Notas |
|----------|-------|-------|
| `NODE_ENV` | `production` | Ambiente de producción |
| `PORT` | `3000` | Puerto (Railway lo asigna automáticamente) |
| `JWT_SECRET` | `tu_clave_super_segura_cambiar_esto` | ⚠️ Cambiar obligatoriamente |
| `WEBHOOK_URL` | `https://hook.us2.make.com/...` | Tu webhook de Make.com |
| `COOKIE_SECURE` | `true` | HTTPS habilitado |
| `CORS_ORIGIN` | `https://tu-dominio.railway.app` | Tu dominio en Railway |

## Paso 4: Configurar Base de Datos

### Opción A: SQLite (Incluido)

La base de datos SQLite se crea automáticamente en el servidor.

```bash
# Inicializar BD en Railway
railway run node init-db.js
```

### Opción B: PostgreSQL (Recomendado para Producción)

1. En Railway Dashboard, click en "New"
2. Seleccionar "PostgreSQL"
3. Conectar a tu proyecto TAHAMUZZA
4. Las variables de conexión se agregarán automáticamente

## Paso 5: Verificar Despliegue

```bash
# 1. Ver logs en tiempo real
railway logs

# 2. Verificar estado
railway status

# 3. Abrir en navegador
railway open
```

## Paso 6: Configurar Dominio Personalizado

1. En Railway Dashboard, ir a "Settings"
2. Click en "Domains"
3. Agregar tu dominio personalizado
4. Configurar DNS según instrucciones de Railway

## Paso 7: Configurar Webhook de Make.com

1. En Make.com, crear nuevo escenario
2. Agregar trigger "Webhook"
3. Copiar URL del webhook
4. Agregar a Railway como variable `WEBHOOK_URL`
5. Reiniciar servicio

## Monitoreo y Mantenimiento

### Ver Logs

```bash
railway logs -f  # Logs en tiempo real
```

### Reiniciar Servicio

```bash
railway redeploy
```

### Actualizar Código

```bash
git add .
git commit -m "Cambios"
git push origin main
# Railway redesplegará automáticamente
```

## Solución de Problemas

### Error: "Port already in use"

Railway asigna el puerto automáticamente. Verificar que `PORT` no esté hardcodeado.

### Error: "Database locked"

SQLite tiene limitaciones. Considerar usar PostgreSQL para producción.

### Error: "CORS error"

Verificar que `CORS_ORIGIN` coincida con tu dominio en Railway.

### Error: "Webhook not responding"

Verificar que `WEBHOOK_URL` sea correcto y accesible.

## Escalado

Para manejar más tráfico:

1. Aumentar recursos en Railway (CPU, RAM)
2. Usar PostgreSQL en lugar de SQLite
3. Agregar caché con Redis
4. Implementar load balancing

## Seguridad en Producción

✅ Cambiar `JWT_SECRET`
✅ Usar HTTPS (Railway lo hace automáticamente)
✅ Configurar CORS correctamente
✅ Usar variables de entorno para secretos
✅ Habilitar 2FA
✅ Implementar rate limiting
✅ Usar PostgreSQL en lugar de SQLite
✅ Configurar backups automáticos

## Costos

Railway ofrece:
- **Tier Gratuito**: $5 USD/mes
- **Pago por uso**: $0.000463 USD/hora de CPU

Para más información: [railway.app/pricing](https://railway.app/pricing)

## Soporte

- Documentación: [docs.railway.app](https://docs.railway.app)
- Discord: [railway.app/discord](https://railway.app/discord)
- Email: support@railway.app

---

**¡Tu portal TAHAMUZZA está listo para producción!** 🎉
