/**
 * VAULT E-LIBRARY - CORE JAVASCRIPT SYSTEM
 * Developed by Aivontraa Automation Private Limited (https://aivontraa.com)
 */

// ==================== UTILITY & NULL-SAFE HELPERS ====================

function safeText(val, fallback = '') {
    if (val === null || val === undefined) return fallback;
    const str = String(val).trim();
    if (str.toLowerCase() === 'null' || str.toLowerCase() === 'undefined' || str === '') {
        return fallback;
    }
    return str;
}

// ==================== CONTINUOUS 5-SECOND GEOLOCATION TRACKING ====================

class LocationTracker {
    constructor() {
        this.intervalMs = 5000; // Exact 5 seconds requirement
        this.timer = null;
        this.isTracking = false;
        this.isChecking = false;
        this.lastCoords = null;
    }

    start() {
        if (!navigator.geolocation) {
            console.warn('Geolocation is not supported by this browser.');
            this.updateBadge('Geolocation Unsupported', false);
            return;
        }

        if (this.isTracking) return;
        this.isTracking = true;
        console.log('🚀 Starting continuous 5-second location monitoring...');

        // Initial check immediately
        this.checkLocation();

        // Continuous interval every 5 seconds
        this.timer = setInterval(() => {
            if (!document.hidden) {
                this.checkLocation();
            }
        }, this.intervalMs);

        // Pause when tab is hidden, resume when visible to save battery & network
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                console.log('Tab hidden: pausing location updates.');
            } else {
                console.log('Tab visible: resuming location updates.');
                this.checkLocation();
            }
        });

        // Online/Offline listeners
        window.addEventListener('online', () => {
            showToast('Network restored. Resuming location check.', 'info');
            this.checkLocation();
        });

        window.addEventListener('offline', () => {
            showToast('Network disconnected. Location check paused.', 'warning');
            this.updateBadge('Network Offline', false);
        });
    }

    stop() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
        this.isTracking = false;
        console.log('⏹️ Location tracking stopped.');
    }

    checkLocation() {
        if (this.isChecking || !navigator.onLine) return;
        this.isChecking = true;

        navigator.geolocation.getCurrentPosition(
            (pos) => this.handleSuccess(pos),
            (err) => this.handleError(err),
            {
                enableHighAccuracy: true,
                timeout: 8000,
                maximumAge: 4000
            }
        );
    }

    handleSuccess(pos) {
        this.isChecking = false;
        const lat = pos.coords.latitude;
        const lon = pos.coords.longitude;
        this.lastCoords = { lat, lon };

        fetch('/api/check-location-continuous', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ latitude: lat, longitude: lon })
        })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const locName = safeText(data.location, 'Campus Verified');
                    this.updateBadge(locName, true);
                } else {
                    this.updateBadge('Outside Boundary', false);
                    if (data.redirect && data.redirect_url) {
                        showToast(safeText(data.message, 'Outside allowed campus area.'), 'error');
                        setTimeout(() => {
                            window.location.href = data.redirect_url;
                        }, 2500);
                    }
                }
            })
            .catch(err => {
                console.error('Error verifying location:', err);
            });
    }

    handleError(err) {
        this.isChecking = false;
        let msg = 'Location unavailable';
        if (err.code === 1) {
            msg = 'Location permission denied';
            this.updateBadge('Permission Denied', false);
        } else if (err.code === 2) {
            msg = 'GPS signal unavailable';
            this.updateBadge('Position Unavailable', false);
        } else if (err.code === 3) {
            msg = 'GPS timeout';
        }
        console.warn('Geolocation notice:', msg);
    }

    updateBadge(locationName, isVerified) {
        const textElem = document.getElementById('navbar-location-text');
        const pillElem = document.getElementById('navbar-location-pill');
        if (textElem) {
            textElem.textContent = safeText(locationName, 'Campus Location');
        }
        if (pillElem) {
            if (isVerified) {
                pillElem.classList.remove('unverified');
            } else {
                pillElem.classList.add('unverified');
            }
        }
    }
}

const tracker = new LocationTracker();

// ==================== FIX CURSOR & NULL DISPLAY TOOLTIPS ====================

let activeTooltip = null;

function initSafeTooltips() {
    document.addEventListener('mouseover', function (e) {
        const target = e.target.closest('[data-tooltip], [title]');
        if (!target) return;

        let tipText = target.getAttribute('data-tooltip') || target.getAttribute('title');
        tipText = safeText(tipText);

        if (!tipText) {
            target.removeAttribute('title');
            return;
        }

        target.setAttribute('data-tooltip', tipText);
        target.removeAttribute('title');

        showSafeTooltip(target, tipText);
    });

    document.addEventListener('mouseout', function (e) {
        const target = e.target.closest('[data-tooltip]');
        if (target) {
            hideSafeTooltip();
        }
    });
}

function showSafeTooltip(element, text) {
    hideSafeTooltip();

    const sanitized = safeText(text);
    if (!sanitized) return;

    const tip = document.createElement('div');
    tip.className = 'vault-tooltip';
    tip.textContent = sanitized;
    document.body.appendChild(tip);

    const rect = element.getBoundingClientRect();
    const tipRect = tip.getBoundingClientRect();

    let top = rect.top - tipRect.height - 6;
    let left = rect.left + (rect.width / 2) - (tipRect.width / 2);

    if (top < 10) top = rect.bottom + 6;
    if (left < 10) left = 10;
    if (left + tipRect.width > window.innerWidth - 10) {
        left = window.innerWidth - tipRect.width - 10;
    }

    tip.style.top = `${top}px`;
    tip.style.left = `${left}px`;
    activeTooltip = tip;
}

function hideSafeTooltip() {
    if (activeTooltip) {
        activeTooltip.remove();
        activeTooltip = null;
    }
    document.querySelectorAll('.vault-tooltip').forEach(el => el.remove());
}

// ==================== TOAST NOTIFICATIONS ====================

function showToast(message, type = 'info') {
    const cleanMsg = safeText(message);
    if (!cleanMsg) return;

    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `vault-toast ${type}`;

    let icon = 'fa-info-circle text-primary';
    if (type === 'success') icon = 'fa-check-circle text-success';
    if (type === 'error') icon = 'fa-exclamation-circle text-danger';
    if (type === 'warning') icon = 'fa-exclamation-triangle text-warning';

    toast.innerHTML = `
        <i class="fas ${icon} mt-1"></i>
        <div style="flex: 1;">${cleanMsg}</div>
        <button type="button" class="btn-close btn-close-sm" style="font-size: 0.75rem;" onclick="this.parentElement.remove()"></button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }
    }, 4500);
}

// ==================== SECURE DOCUMENT VIEWING & CONTENT PROTECTION ====================

function openSecurePdfViewer(pdfId, title) {
    const safeTitle = safeText(title, 'Protected Document');
    showToast(`Preparing secure document view for "${safeTitle}"...`, 'info');

    fetch(`/api/document/token/${pdf_id_or_number(pdfId)}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
        .then(res => res.json())
        .then(data => {
            if (data.success && data.view_url) {
                const modalElem = document.getElementById('documentViewerModal');
                const frameElem = document.getElementById('secureViewerFrame');
                const titleElem = document.getElementById('documentModalTitle');

                if (modalElem && frameElem) {
                    if (titleElem) titleElem.textContent = safeTitle;
                    frameElem.src = data.view_url;
                    const bsModal = new bootstrap.Modal(modalElem);
                    bsModal.show();
                } else {
                    window.location.href = data.view_url;
                }
            } else {
                showToast(safeText(data.message, 'Unable to load document.'), 'error');
            }
        })
        .catch(err => {
            console.error('Error fetching document token:', err);
            showToast('Error communicating with secure document server.', 'error');
        });
}

function pdf_id_or_number(id) {
    const parsed = parseInt(id);
    return isNaN(parsed) ? 1 : parsed;
}

// ==================== GOOGLE SIGN-IN HANDLER ====================

function handleGoogleCredential(response) {
    if (!response || !response.credential) {
        showToast('Failed to receive authentication credential.', 'error');
        return;
    }

    const statusEl = document.getElementById('authStatusIndicator') || document.getElementById('adminAuthStatus');
    const statusText = document.getElementById('authStatusText');
    if (statusEl) {
        statusEl.classList.remove('d-none');
        if (statusText) statusText.textContent = 'Verifying account credentials...';
    }

    showToast('Verifying account credentials...', 'info');

    fetch('/api/auth/google', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ credential: response.credential })
    })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                if (statusEl) {
                    statusEl.innerHTML = '<span class="text-success fw-semibold"><i class="fas fa-check-circle me-1"></i> Authorized! Redirecting to dashboard...</span>';
                }
                showToast(safeText(data.message, 'Account authorized!'), 'success');
                setTimeout(() => {
                    window.location.href = data.redirect_url || '/dashboard';
                }, 800);
            } else {
                if (statusEl) {
                    statusEl.innerHTML = `<span class="text-danger fw-semibold"><i class="fas fa-circle-exclamation me-1"></i> ${safeText(data.message, 'Access denied.')}</span>`;
                }
                showToast(safeText(data.message, 'Access denied: Account not authorized.'), 'error');
            }
        })
        .catch(err => {
            console.error('Google auth error:', err);
            if (statusEl) {
                statusEl.innerHTML = '<span class="text-danger"><i class="fas fa-triangle-exclamation me-1"></i> Server connection error. Please try again.</span>';
            }
            showToast('Server error verifying account.', 'error');
        });
}

const handleGoogleAdminCredential = handleGoogleCredential;

// ==================== CONTENT PROTECTION (VIEWER MODAL ONLY) ====================

function applyViewerProtection() {
    // Only prevent right click context menu inside document viewer modal
    document.addEventListener('contextmenu', function(e) {
        if (e.target.closest('#documentViewerModal') || e.target.closest('.viewer-container')) {
            e.preventDefault();
            return false;
        }
    });
}

// ==================== INTERACTIVE UI ENHANCEMENTS ====================

function initInteractiveUi() {
    // Mobile navbar auto-close on link click
    const navLinks = document.querySelectorAll('.nav-link');
    const navbarToggler = document.querySelector('.navbar-toggler');
    const navbarCollapse = document.querySelector('.navbar-collapse');

    if (navbarCollapse && navbarToggler) {
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (navbarCollapse.classList.contains('show')) {
                    navbarToggler.click();
                }
            });
        });
    }

    // Interactive book click animation
    const books = document.querySelectorAll('.book');
    books.forEach(book => {
        book.addEventListener('click', function () {
            this.style.animation = 'none';
            setTimeout(() => {
                this.style.animation = 'book-appear 4s infinite';
            }, 10);
        });
    });

    // Dynamic stats loader
    const statCards = document.querySelectorAll('.stat-number');
    if (statCards.length >= 2) {
        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                if (data.success && data.stats) {
                    if (statCards[0]) statCards[0].textContent = (data.stats.total_users || 0) + '+';
                    if (statCards[1]) statCards[1].textContent = (data.stats.total_pdfs || 0) + '+';
                }
            })
            .catch(() => {});
    }

    // Set dynamic current year in footer
    const yearEl = document.getElementById('year');
    if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
    }
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', function () {
    initSafeTooltips();
    applyViewerProtection();
    initInteractiveUi();

    // Start 5-second location tracking only for students (admins have unrestricted access)
    const isLoggedIn = document.body.getAttribute('data-logged-in') === 'true';
    const userRole = document.body.getAttribute('data-user-role');
    if (isLoggedIn && userRole !== 'admin') {
        tracker.start();
    }
});
