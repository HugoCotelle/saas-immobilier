/* Consentement aux cookies de mesure publicitaire (Google Ads et Pixel Meta) sur les pages publiques de Zelyro.
   Rien de Google ni de Meta n'est chargé tant que le visiteur n'a pas cliqué sur « Accepter ».
   Le choix est mémorisé 6 mois dans le navigateur, puis redemandé. Il peut être modifié à tout
   moment depuis le lien « Gérer mes cookies » en bas de page.
   Ce script n'est pas inclus dans l'espace connecté ni sur la page de connexion. */
(function () {
    'use strict';

    var ADS_ID = 'AW-18528941154';
    // Libellé de la conversion « Demande de démo », fourni par Google Ads (Objectifs > Conversions),
    // de la forme 'AbCdEfGhIjKl'. Tant qu'il est vide, les visites sont mesurées mais pas la demande de démo.
    var CONVERSION_LABEL = '';

    // Pixel Meta (Facebook / Instagram) : seule mesure des demandes de démonstration issues des annonces Meta.
    // Aucune donnée saisie dans le formulaire n'est transmise ; la collecte automatique du Pixel est désactivée.
    var META_ID = '1647203577149798';
    // Version du texte de consentement : 2 = le bandeau mentionne Google et Meta. Un « oui » donné avant
    // (sans version) ne vaut que pour Google : le Pixel Meta n'est jamais chargé avec cet ancien accord.
    var VERSION = 2;

    var CLE = 'zelyro_cookies';
    var DUREE = 182 * 24 * 3600 * 1000;   // 6 mois
    var enligne = /(^|\.)zelyro\.fr$/.test(location.hostname);   // ni aperçus ni tests locaux

    function lire() {
        try {
            var v = JSON.parse(localStorage.getItem(CLE) || 'null');
            if (v && (v.c === 'oui' || v.c === 'non') && Date.now() - v.t < DUREE) return v.c;
        } catch (e) { /* stockage indisponible */ }
        return null;
    }
    function ecrire(c) {
        try { localStorage.setItem(CLE, JSON.stringify({ c: c, t: Date.now(), v: VERSION })); } catch (e) { /* ignoré */ }
    }
    // Vrai seulement si le visiteur a accepté avec le bandeau qui mentionne Meta.
    function metaAccepte() {
        try {
            var v = JSON.parse(localStorage.getItem(CLE) || 'null');
            return !!(v && v.c === 'oui' && v.v >= 2 && Date.now() - v.t < DUREE);
        } catch (e) { return false; }
    }
    function signalRefus() {
        var n = navigator;
        return n.doNotTrack === '1' || window.doNotTrack === '1' || n.msDoNotTrack === '1' || n.globalPrivacyControl;
    }

    // La page de confirmation n'est mesurée que juste après l'envoi d'une demande (drapeau posé par
    // demande-demo.js, qui contient l'identifiant unique de cette demande) : une visite directe ou un
    // rechargement de la page ne compte pas comme une demande. Le drapeau est lu une seule fois puis effacé.
    var demande = null;
    function lireDemande() {
        if (demande) return demande;
        demande = { ok: false, id: null, stockage: true };
        try {
            var v = sessionStorage.getItem('zelyro_demande_ok');
            if (v) {
                sessionStorage.removeItem('zelyro_demande_ok');
                demande.ok = true;
                demande.id = v === '1' ? 'd' + Date.now().toString(36) : v;   // '1' : ancien format du drapeau
            }
        } catch (e) { demande.ok = true; demande.stockage = false; }   // stockage indisponible : mesure Google conservée, jamais Meta
        return demande;
    }
    var surMerci = location.pathname.indexOf('demo-merci') !== -1;

    function charger() {
        if (!enligne) return;
        if (surMerci && !lireDemande().ok) return;   // visite directe ou rechargement de la page de confirmation : aucune mesure
        chargerGoogle();
        if (metaAccepte()) chargerMeta();
    }

    function chargerGoogle() {
        if (window.__zelyroAds) return;
        window.__zelyroAds = true;
        window.dataLayer = window.dataLayer || [];
        window.gtag = function () { window.dataLayer.push(arguments); };
        // Google Consent Mode v2 : tout est refusé par défaut, puis ce que le visiteur vient d'accepter est
        // accordé. La bannière ne parle que de mesure des annonces : pas de personnalisation publicitaire.
        window.gtag('consent', 'default', { ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied', analytics_storage: 'denied' });
        window.gtag('consent', 'update', { ad_storage: 'granted', ad_user_data: 'granted', ad_personalization: 'denied', analytics_storage: 'denied' });
        window.gtag('js', new Date());
        window.gtag('config', ADS_ID);
        var s = document.createElement('script');
        s.async = true;
        s.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(ADS_ID);
        document.head.appendChild(s);
        if (CONVERSION_LABEL && surMerci) {
            var deja = false;
            try { deja = sessionStorage.getItem('zelyro_conv') === '1'; } catch (e) { /* ignoré */ }
            if (!deja) {
                window.gtag('event', 'conversion', { send_to: ADS_ID + '/' + CONVERSION_LABEL });
                try { sessionStorage.setItem('zelyro_conv', '1'); } catch (e) { /* ignoré */ }
            }
        }
    }

    function chargerMeta() {
        if (window.__zelyroMeta || window.fbq) return;
        window.__zelyroMeta = true;
        // Amorce officielle du Pixel Meta, adaptée : chargée seulement après accord, sans balise <noscript>.
        var n = window.fbq = function () { n.callMethod ? n.callMethod.apply(n, arguments) : n.queue.push(arguments); };
        if (!window._fbq) window._fbq = n;
        n.push = n; n.loaded = true; n.version = '2.0'; n.queue = [];
        n('set', 'autoConfig', false, META_ID);   // pas de collecte automatique (clics, champs de formulaire, mise en correspondance)
        n('init', META_ID);                       // aucune donnée personnelle transmise
        n('track', 'PageView');
        // Lead : uniquement juste après une demande de démonstration acceptée par le serveur, une seule fois par demande.
        if (surMerci && demande && demande.ok && demande.stockage && demande.id) {
            var cleLead = 'zelyro_lead_' + demande.id, deja = false;
            try { deja = sessionStorage.getItem(cleLead) === '1'; sessionStorage.setItem(cleLead, '1'); } catch (e) { deja = true; }
            if (!deja) n('track', 'Lead', {}, { eventID: demande.id });
        }
        var s = document.createElement('script');
        s.async = true;
        s.src = 'https://connect.facebook.net/en_US/fbevents.js';
        document.head.appendChild(s);
    }

    function effacerCookiesGoogle() {
        var noms = document.cookie.split(';');
        var hotes = [location.hostname, '.' + location.hostname.replace(/^www\./, '')];
        for (var i = 0; i < noms.length; i++) {
            var nom = noms[i].split('=')[0].replace(/^\s+/, '');
            if (/^(_gcl_|_gac_|_ga|_gid|_fbp|_fbc)/.test(nom)) {
                for (var j = 0; j < hotes.length; j++) {
                    document.cookie = nom + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=' + hotes[j];
                }
                document.cookie = nom + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
            }
        }
    }

    var banniere = null;

    var defilementAvant = null;
    function fermer() {
        if (banniere && banniere.parentNode) banniere.parentNode.removeChild(banniere);
        banniere = null;
        if (defilementAvant !== null) { document.documentElement.style.overflow = defilementAvant; defilementAvant = null; }
    }
    function choisir(c) {
        var avant = lire();
        ecrire(c);
        fermer();
        if (c === 'oui') {
            charger();
        } else {
            effacerCookiesGoogle();
            if (avant === 'oui' && (window.__zelyroAds || window.__zelyroMeta)) location.reload();   // décharge ce qui a déjà été chargé
        }
    }

    function style() {
        if (document.getElementById('cookies-style')) return;
        var st = document.createElement('style');
        st.id = 'cookies-style';
        st.textContent =
            '.cookies-voile{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9999;display:flex;align-items:center;' +
            'justify-content:center;padding:16px;background:rgba(10,13,11,.6)}' +
            '.cookies-bandeau{width:100%;max-width:460px;background:#fff;color:#0A0D0B;border:1px solid #B9BDB5;border-radius:8px;' +
            'padding:26px 26px 24px;box-shadow:0 8px 32px rgba(10,13,11,.28);font:400 15px/1.55 "Hanken Grotesk",system-ui,sans-serif}' +
            '.cookies-bandeau:focus{outline:none}' +
            '.cookies-bandeau h2{font:700 20px/1.25 "Familjen Grotesk","Hanken Grotesk",system-ui,sans-serif;margin:0 0 10px;color:#0A0D0B}' +
            '.cookies-bandeau p{margin:0 0 20px;color:#2b302c}' +
            '.cookies-bandeau a{color:#0A0D0B;text-decoration:underline;text-decoration-color:#39FF14;text-decoration-thickness:2px;text-underline-offset:3px}' +
            '.cookies-actions{display:flex;gap:12px}' +
            '.cookies-actions button{flex:1;font:600 15px/1 "Hanken Grotesk",system-ui,sans-serif;padding:14px;' +
            'background:#fff;color:#0A0D0B;border:1.5px solid #0A0D0B;border-radius:6px;cursor:pointer;min-height:48px}' +
            '.cookies-actions button:hover,.cookies-actions button:focus-visible{background:#39FF14;outline:none}' +
            '.cookies-actions button:focus-visible{box-shadow:0 0 0 2px #fff,0 0 0 4px #0A0D0B}' +
            '@media (max-width:520px){.cookies-bandeau{padding:22px 20px 20px}.cookies-actions{flex-direction:column}}';
        document.head.appendChild(st);
    }

    function afficher(focus) {
        if (banniere) return;
        style();
        // Fenêtre au centre de l'écran : le visiteur doit faire un choix (Refuser ou Accepter, à égalité)
        // avant de continuer. Aucun des deux boutons n'est mis en avant par rapport à l'autre.
        banniere = document.createElement('div');
        banniere.className = 'cookies-voile';
        banniere.innerHTML =
            '<div class="cookies-bandeau" role="dialog" aria-modal="true" aria-labelledby="cookies-titre" tabindex="-1">' +
            '<h2 id="cookies-titre">Cookies et mesure publicitaire</h2>' +
            '<p>Nous aimerions mesurer l’effet de nos annonces Google et Meta (Facebook, Instagram) sur le nombre de demandes de démonstration. ' +
            'Cela dépose des cookies de Google et de Meta sur votre navigateur. Vous pouvez refuser : le site fonctionne de la même façon. ' +
            '<a href="/confidentialite.html#cookies">En savoir plus</a></p>' +
            '<div class="cookies-actions"><button type="button" data-choix="non">Refuser</button>' +
            '<button type="button" data-choix="oui">Accepter</button></div></div>';
        banniere.addEventListener('click', function (e) {
            var b = e.target.closest ? e.target.closest('button[data-choix]') : null;
            if (b) choisir(b.getAttribute('data-choix'));
        });
        banniere.addEventListener('keydown', function (e) {   // le clavier reste dans la fenêtre tant qu'elle est ouverte
            if (e.key !== 'Tab') return;
            var els = banniere.querySelectorAll('button, a[href]');
            var premier = els[0], dernier = els[els.length - 1];
            if (e.shiftKey && document.activeElement === premier) { e.preventDefault(); dernier.focus(); }
            else if (!e.shiftKey && document.activeElement === dernier) { e.preventDefault(); premier.focus(); }
        });
        defilementAvant = document.documentElement.style.overflow;
        document.documentElement.style.overflow = 'hidden';
        document.body.appendChild(banniere);
        var fenetre = banniere.querySelector('.cookies-bandeau');   // le focus va à la fenêtre, sans mettre un bouton en avant
        if (fenetre) fenetre.focus();
    }

    function demarrer() {
        document.addEventListener('click', function (e) {
            var a = e.target.closest ? e.target.closest('[data-gerer-cookies]') : null;
            if (a) { e.preventDefault(); afficher(true); }
        });
        var c = lire();
        if (surMerci) {
            // Le drapeau est consommé tout de suite. Si le visiteur n'avait pas accepté avant la demande, rien ne
            // sera envoyé a posteriori, même s'il accepte ensuite sur cette page.
            lireDemande();
            if (c !== 'oui' || signalRefus()) demande.ok = false;
        }
        if (signalRefus()) return;   // « Ne pas me suivre » ou Global Privacy Control : traité comme un refus
        if (c === 'oui') charger();
        else if (c === null) afficher(false);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', demarrer);
    else demarrer();
})();
