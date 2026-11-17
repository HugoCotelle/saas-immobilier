/* Mesure d'audience anonyme de Zelyro (sans cookie, sans service tiers).
   Envoie à notre propre serveur la page vue, la provenance du lien et la largeur d'écran.
   Rien n'est envoyé si le visiteur a activé « Ne pas me suivre », s'il s'est exclu de la
   mesure (voir la politique de confidentialité) ou s'il est connecté à Zelyro. */
(function () {
    'use strict';
    try {
        var API = 'https://saas-immobilier-921a.onrender.com';
        var nav = navigator;
        if (nav.doNotTrack === '1' || window.doNotTrack === '1' || nav.msDoNotTrack === '1' || nav.globalPrivacyControl) return;
        if (!/(^|\.)zelyro\.fr$/.test(location.hostname)) return;   // ni aperçus ni tests locaux
        try {
            if (localStorage.getItem('zelyro_no_stats') === '1') return;
            if (localStorage.getItem('token')) return;              // l'équipe et les agences connectées ne sont pas comptées
        } catch (e) { /* stockage indisponible : on mesure quand même */ }

        function envoyer(chemin, corps) {
            try {
                var p = fetch(API + chemin, {
                    method: 'POST', body: JSON.stringify(corps), keepalive: true,
                    mode: 'no-cors', credentials: 'omit', cache: 'no-store'
                });
                if (p && p.catch) p.catch(function () {});
            } catch (e) { /* la mesure ne doit jamais gêner la page */ }
        }

        var page = location.pathname || '/';
        var largeur = window.innerWidth || (screen && screen.width) || 0;
        var corps = { p: page, w: largeur };
        try {
            var q = new URLSearchParams(location.search);
            if (q.get('utm_source')) corps.s = String(q.get('utm_source')).slice(0, 80);
            if (q.get('utm_campaign')) corps.c = String(q.get('utm_campaign')).slice(0, 80);
        } catch (e) { /* navigateur ancien */ }
        // Si le visiteur a changé de page sur zelyro.fr, le site d'origine (nom de domaine seul) est reporté dans l'adresse
        // des liens vers la démonstration (voir relayerOrigine) : on le retrouve ici.
        var ref = document.referrer || '';
        try {
            var rh0 = new URLSearchParams(location.search).get('rh');
            var hoteRef = ref ? new URL(ref).hostname : '';
            if (rh0 && /^[a-z0-9.-]{1,120}$/i.test(rh0) && (!hoteRef || /(^|\.)zelyro\.fr$/.test(hoteRef))) ref = 'https://' + rh0;
        } catch (e) { /* adresse invalide : on garde le référent d'origine */ }
        if (ref) corps.r = ref.slice(0, 300);

        envoyer('/public/stats/vue', corps);

        // Origine jusqu'au formulaire de démonstration. Les liens vers /demo-agences.html reprennent, dans leur adresse :
        // les paramètres de campagne de la page, un drapeau de clic publicitaire (« cp », jamais l'identifiant du clic) ou
        // le NOM DE DOMAINE SEUL du site d'où vient le visiteur (« rh », jamais le chemin ni les paramètres). Rien n'est
        // stocké dans le navigateur : l'information ne part que si le visiteur envoie lui-même le formulaire.
        function relayerOrigine() {
            try {
                var q = new URLSearchParams(location.search), porte = {};
                ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'].forEach(function (k) {
                    var v = q.get(k);
                    if (v) porte[k] = String(v).slice(0, 120);
                });
                var cp = q.get('cp');
                if (cp === 'meta' || cp === 'google') porte.cp = cp;
                else if (q.get('fbclid')) porte.cp = 'meta';
                else if (q.get('gclid') || q.get('gbraid') || q.get('wbraid')) porte.cp = 'google';
                var rh = q.get('rh');
                if (rh && /^[a-z0-9.-]{1,120}$/i.test(rh)) porte.rh = rh.toLowerCase();
                if (document.referrer) {
                    var h = new URL(document.referrer).hostname.toLowerCase().replace(/^www\./, '');
                    if (h && !/(^|\.)zelyro\.fr$/.test(h)) porte.rh = h.slice(0, 120);
                }
                var cles = Object.keys(porte);
                if (!cles.length) return;
                var liens = document.querySelectorAll('a[href]');
                for (var i = 0; i < liens.length; i++) {
                    var u;
                    try { u = new URL(liens[i].getAttribute('href'), location.href); } catch (e) { continue; }
                    if (u.origin !== location.origin || !/^\/demo-agences(\.html)?$/.test(u.pathname)) continue;
                    cles.forEach(function (k) { if (!u.searchParams.has(k)) u.searchParams.set(k, porte[k]); });
                    liens[i].setAttribute('href', u.pathname + u.search + u.hash);
                }
            } catch (e) { /* la mesure ne doit jamais gêner la page */ }
        }
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', relayerOrigine);
        else relayerOrigine();

        // Signe de vie toutes les 30 secondes tant que la page est visible : c'est ce qui
        // permet de compter les personnes « en direct ».
        var presence = { p: page, w: largeur };
        function battement() {
            if (document.visibilityState !== 'hidden') envoyer('/public/stats/presence', presence);
        }
        setInterval(battement, 30000);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'visible') battement();
        });
    } catch (e) { /* ignoré */ }
})();
