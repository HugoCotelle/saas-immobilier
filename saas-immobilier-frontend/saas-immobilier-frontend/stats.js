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
        if (document.referrer) corps.r = document.referrer.slice(0, 300);

        envoyer('/public/stats/vue', corps);

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
