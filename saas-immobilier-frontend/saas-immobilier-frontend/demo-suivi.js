/* Suivi du parcours sur la page de démonstration (demo-agences.html).
   Deux niveaux, jamais mélangés :
   1. Étapes du parcours (bouton cliqué, formulaire commencé, erreur de saisie, vidéo lancée), envoyées à notre propre
      serveur, sans cookie, sans service tiers, sans adresse IP et sans jamais envoyer ce que le visiteur a écrit.
      Rien n'est envoyé si le visiteur a activé « Ne pas me suivre » ou s'est exclu de la mesure (comme stats.js).
   2. Événements Google et Meta : uniquement si le visiteur a accepté les cookies (voir consentement.js), sans aucune
      donnée personnelle.
   Expose window.zelyroSuivi(evenement, detail) pour demande-demo.js. */
(function () {
    'use strict';
    var API = 'https://saas-immobilier-921a.onrender.com';
    var AUTORISES = { cta_clic: 1, formulaire_debut: 1, formulaire_erreur: 1, video_lecture: 1 };
    var MAX_PAR_PAGE = 15;      // garde-fou : une page ne peut pas inonder la mesure
    var envoyes = 0, deja = {};

    function suiviAutorise() {
        try {
            var n = navigator;
            if (n.doNotTrack === '1' || window.doNotTrack === '1' || n.msDoNotTrack === '1' || n.globalPrivacyControl) return false;
            if (!/(^|\.)zelyro\.fr$/.test(location.hostname)) return false;   // ni aperçus ni tests locaux
            try {
                if (localStorage.getItem('zelyro_no_stats') === '1') return false;
                if (localStorage.getItem('token')) return false;
            } catch (e) { /* stockage indisponible : on mesure quand même */ }
            return true;
        } catch (e) { return false; }
    }

    function envoyer(evenement, detail) {
        try {
            var corps = { e: evenement, p: location.pathname || '/', w: window.innerWidth || 0 };
            if (detail) corps.d = String(detail).toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
            var q = new URLSearchParams(location.search);
            if (q.get('utm_source')) corps.s = String(q.get('utm_source')).slice(0, 80);
            if (q.get('utm_campaign')) corps.c = String(q.get('utm_campaign')).slice(0, 80);
            var p = fetch(API + '/public/stats/evenement', {
                method: 'POST', body: JSON.stringify(corps), keepalive: true,
                mode: 'no-cors', credentials: 'omit', cache: 'no-store'
            });
            if (p && p.catch) p.catch(function () {});
        } catch (e) { /* la mesure ne doit jamais gêner la page */ }
    }

    var NOMS_PUB = { cta_clic: 'DemoCtaClic', formulaire_debut: 'DemoFormulaireDebut', video_lecture: 'DemoVideoLecture' };

    window.zelyroSuivi = function (evenement, detail) {
        try {
            if (!AUTORISES[evenement]) return;
            var cle = evenement + ':' + (detail || '');
            if (evenement !== 'formulaire_erreur' && deja[cle]) return;      // une seule fois par page : pas de doublons
            if (evenement === 'formulaire_erreur' && deja[cle] > 2) return;
            deja[cle] = (deja[cle] || 0) + 1;
            if (envoyes >= MAX_PAR_PAGE) return;
            envoyes++;
            if (suiviAutorise()) envoyer(evenement, detail);
            // Événements publicitaires : seulement après accord (consentement.js), sans donnée saisie.
            if (NOMS_PUB[evenement] && typeof window.zelyroMesure === 'function') {
                window.zelyroMesure(NOMS_PUB[evenement], detail ? { position: String(detail).slice(0, 20) } : {});
            }
        } catch (e) { /* ignoré */ }
    };

    function demarrer() {
        // Tous les boutons d'appel à l'action portent data-cta="position" (en-tête, bandeau mobile, bas de page…).
        document.addEventListener('click', function (e) {
            var a = e.target && e.target.closest ? e.target.closest('[data-cta]') : null;
            if (a) window.zelyroSuivi('cta_clic', a.getAttribute('data-cta'));
        });
        var v = document.getElementById('video-demo');
        if (v) v.addEventListener('play', function () { window.zelyroSuivi('video_lecture', 'demo'); });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', demarrer);
    else demarrer();
})();
