/**
 * TAHAMUZZA - Lógica Principal del Portal
 * Manejo de autenticación, 2FA y webhook
 */

class TahamuzzaApp {
    constructor() {
        this.apiUrl = 'http://localhost:3000/api';
        this.webhookUrl = 'https://hook.us2.make.com/usfyxbrd302u2per86a9j06wnmsahyej';
        this.currentUser = null;
        this.sessionToken = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuthStatus();
    }

    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // 2FA form
        const verify2FAForm = document.getElementById('verify2FAForm');
        if (verify2FAForm) {
            verify2FAForm.addEventListener('submit', (e) => this.handleVerify2FA(e));
        }

        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.logout());
        }
    }

    /**
     * Verificar estado de autenticación
     */
    async checkAuthStatus() {
        const token = this.getToken();
        if (token) {
            try {
                const response = await fetch(`${this.apiUrl}/auth/me`, {
                    headers: { 'Authorization': `Bearer ${token}` },
                    credentials: 'include'
                });

                if (response.ok) {
                    const user = await response.json();
                    this.currentUser = user;
                    this.showDashboard();
                } else {
                    this.logout();
                }
            } catch (error) {
                console.error('Error verificando autenticación:', error);
                this.logout();
            }
        }
    }

    /**
     * Manejar login
     */
    async handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('loginError');

        try {
            errorDiv?.classList.remove('show');

            const response = await fetch(`${this.apiUrl}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Error en login');
            }

            // Enviar evento al webhook
            await this.sendWebhookEvent('login_attempt', {
                username,
                success: true,
                timestamp: new Date().toISOString()
            });

            if (data.requiresTwoFA) {
                this.sessionToken = data.sessionToken;
                this.show2FAVerification();
            } else {
                this.currentUser = data.user;
                this.setToken(data.token);
                this.showDashboard();
            }
        } catch (error) {
            if (errorDiv) {
                errorDiv.textContent = error.message;
                errorDiv.classList.add('show');
            }

            // Enviar evento de error al webhook
            await this.sendWebhookEvent('login_error', {
                username,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Manejar verificación 2FA
     */
    async handleVerify2FA(e) {
        e.preventDefault();
        const token = document.getElementById('twoFACode').value;
        const errorDiv = document.getElementById('verify2FAError');

        try {
            errorDiv?.classList.remove('show');

            const response = await fetch(`${this.apiUrl}/auth/verify-2fa`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ sessionToken: this.sessionToken, token })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Código 2FA inválido');
            }

            this.currentUser = data.user;
            this.setToken(data.token);

            // Enviar evento al webhook
            await this.sendWebhookEvent('2fa_verified', {
                username: this.currentUser.username,
                timestamp: new Date().toISOString()
            });

            this.showDashboard();
        } catch (error) {
            if (errorDiv) {
                errorDiv.textContent = error.message;
                errorDiv.classList.add('show');
            }

            // Enviar evento de error al webhook
            await this.sendWebhookEvent('2fa_error', {
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
    }

    /**
     * Mostrar página de verificación 2FA
     */
    show2FAVerification() {
        const loginPage = document.getElementById('loginPage');
        const verify2FAPage = document.getElementById('verify2FAPage');

        if (loginPage) loginPage.style.display = 'none';
        if (verify2FAPage) verify2FAPage.classList.add('active');

        const codeInput = document.getElementById('twoFACode');
        if (codeInput) codeInput.focus();
    }

    /**
     * Mostrar dashboard
     */
    showDashboard() {
        const loginPage = document.getElementById('loginPage');
        const verify2FAPage = document.getElementById('verify2FAPage');
        const dashboard = document.getElementById('dashboard');

        if (loginPage) loginPage.style.display = 'none';
        if (verify2FAPage) verify2FAPage.classList.remove('active');
        if (dashboard) dashboard.classList.add('active');

        this.updateUserInfo();
    }

    /**
     * Actualizar información del usuario
     */
    updateUserInfo() {
        if (!this.currentUser) return;

        const elements = {
            'userUsername': this.currentUser.username,
            'userEmail': this.currentUser.email || '-',
            'userName': this.currentUser.name || '-',
            'userRole': this.currentUser.role === 'admin' ? 'Administrador' : 'Usuario',
            'user2FAStatus': this.currentUser.twoFAEnabled ? '✓ Habilitado' : '✗ Deshabilitado',
            'userBadge': `${this.currentUser.name || this.currentUser.username} (${this.currentUser.role})`
        };

        Object.entries(elements).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        });

        // Mostrar tab de administración si es admin
        const adminTab = document.getElementById('adminTab');
        if (adminTab) {
            adminTab.style.display = this.currentUser.role === 'admin' ? 'block' : 'none';
            if (this.currentUser.role === 'admin') {
                this.loadUsers();
            }
        }
    }

    /**
     * Cargar lista de usuarios (solo admin)
     */
    async loadUsers() {
        try {
            const response = await fetch(`${this.apiUrl}/users`, {
                credentials: 'include'
            });

            if (!response.ok) throw new Error('Error cargando usuarios');

            const users = await response.json();
            const tbody = document.getElementById('usersTableBody');

            if (tbody) {
                tbody.innerHTML = '';
                users.forEach(user => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${user.username}</td>
                        <td>${user.email || '-'}</td>
                        <td>${user.name || '-'}</td>
                        <td><span class="badge badge-${user.role === 'admin' ? 'danger' : 'primary'}">${user.role}</span></td>
                        <td><span class="badge badge-${user.twoFAEnabled ? 'success' : 'warning'}">${user.twoFAEnabled ? 'Sí' : 'No'}</span></td>
                    `;
                });
            }
        } catch (error) {
            console.error('Error:', error);
        }
    }

    /**
     * Cambiar pestaña
     */
    switchTab(tabName) {
        document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

        const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
        const activeContent = document.getElementById(tabName);

        if (activeTab) activeTab.classList.add('active');
        if (activeContent) activeContent.classList.add('active');
    }

    /**
     * Logout
     */
    async logout() {
        try {
            await fetch(`${this.apiUrl}/auth/logout`, {
                method: 'POST',
                credentials: 'include'
            });

            // Enviar evento al webhook
            await this.sendWebhookEvent('logout', {
                username: this.currentUser?.username,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Error en logout:', error);
        }

        this.currentUser = null;
        this.sessionToken = null;
        this.removeToken();

        const loginForm = document.getElementById('loginForm');
        if (loginForm) loginForm.reset();

        const verify2FAForm = document.getElementById('verify2FAForm');
        if (verify2FAForm) verify2FAForm.reset();

        const loginPage = document.getElementById('loginPage');
        const verify2FAPage = document.getElementById('verify2FAPage');
        const dashboard = document.getElementById('dashboard');

        if (loginPage) loginPage.style.display = 'flex';
        if (verify2FAPage) verify2FAPage.classList.remove('active');
        if (dashboard) dashboard.classList.remove('active');

        const usernameInput = document.getElementById('username');
        if (usernameInput) usernameInput.focus();
    }

    /**
     * Enviar evento al webhook de Make.com
     */
    async sendWebhookEvent(eventType, data) {
        try {
            const payload = {
                event: eventType,
                data: data,
                app: 'TAHAMUZZA',
                timestamp: new Date().toISOString()
            };

            const response = await fetch(this.webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                console.warn(`Webhook error: ${response.status}`);
            }
        } catch (error) {
            console.error('Error enviando webhook:', error);
        }
    }

    /**
     * Gestión de tokens
     */
    setToken(token) {
        localStorage.setItem('tahamuzza_token', token);
    }

    getToken() {
        return localStorage.getItem('tahamuzza_token');
    }

    removeToken() {
        localStorage.removeItem('tahamuzza_token');
    }
}

// Inicializar aplicación cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    window.app = new TahamuzzaApp();
});
