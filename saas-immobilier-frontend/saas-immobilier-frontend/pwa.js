/* Application installable et notifications de Zelyro (pages connectées).
   Expose window.zelyroPwa pour la page « Mon compte ». */
(function () {
    var API_URL = 'https://saas-immobilier-921a.onrender.com';
    var installation = null;

    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function () {
            navigator.serviceWorker.register('/sw.js').catch(function () { /* sans conséquence */ });
        });
    }
    window.addEventListener('beforeinstallprompt', function (e) { e.preventDefault(); installation = e; });
    window.addEventListener('appinstalled', function () { installation = null; });

    function appel(chemin, options) {
        var o = options || {};
        return fetch(API_URL + chemin, {
            method: o.method || 'GET',
            headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token'), 'Content-Type': 'application/json' },
            body: o.body
        }).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (j) {
                if (!r.ok) throw new Error(j.message || ('Erreur ' + r.status));
                return j;
            });
        });
    }

    function cleServeur(base64) {
        var rempli = (base64 + '='.repeat((4 - base64.length % 4) % 4)).replace(/-/g, '+').replace(/_/g, '/');
        var brut = atob(rempli), sortie = new Uint8Array(brut.length);
        for (var i = 0; i < brut.length; i++) sortie[i] = brut.charCodeAt(i);
        return sortie;
    }

    var estIphone = /iPhone|iPad|iPod/.test(navigator.userAgent);
    var estInstallee = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || navigator.standalone === true;

    window.zelyroPwa = {
        // L'appareil sait-il recevoir des notifications ? Sur iPhone, seulement une fois l'appli ajoutée à l'écran d'accueil.
        supporte: function () { return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window; },
        iphoneAInstaller: function () { return estIphone && !estInstallee; },
        installable: function () { return installation !== null; },
        installee: function () { return estInstallee; },
        installer: function () {
            if (!installation) return Promise.resolve(false);
            var e = installation; installation = null;
            e.prompt();
            return e.userChoice.then(function (c) { return c.outcome === 'accepted'; });
        },
        etat: function () {
            if (!this.supporte()) return Promise.resolve({ permission: 'unsupported', abonne: false });
            return navigator.serviceWorker.ready.then(function (reg) { return reg.pushManager.getSubscription(); })
                .then(function (s) { return { permission: Notification.permission, abonne: !!s }; })
                .catch(function () { return { permission: Notification.permission, abonne: false }; });
        },
        activer: function () {
            return appel('/api/v1/push/config').then(function (cfg) {
                if (!cfg.enabled) throw new Error("Les notifications ne sont pas encore activées sur ce service.");
                return Notification.requestPermission().then(function (p) {
                    if (p !== 'granted') throw new Error("Notifications refusées : autorisez-les dans les réglages de votre navigateur pour ce site.");
                    return navigator.serviceWorker.ready;
                }).then(function (reg) {
                    return reg.pushManager.getSubscription().then(function (existant) {
                        return existant || reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: cleServeur(cfg.public_key) });
                    });
                }).then(function (s) {
                    return appel('/api/v1/push/subscribe', { method: 'POST', body: JSON.stringify(s.toJSON()) });
                });
            });
        },
        desactiver: function () {
            return navigator.serviceWorker.ready.then(function (reg) { return reg.pushManager.getSubscription(); }).then(function (s) {
                if (!s) return null;
                var endpoint = s.endpoint;
                return appel('/api/v1/push/unsubscribe', { method: 'POST', body: JSON.stringify({ endpoint: endpoint }) })
                    .catch(function () { /* on retire quand même l'appareil */ })
                    .then(function () { return s.unsubscribe(); });
            });
        },
        essai: function () { return appel('/api/v1/push/test', { method: 'POST' }); }
    };
})();
