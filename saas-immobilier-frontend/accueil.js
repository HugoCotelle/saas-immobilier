/* Parcours d'accueil : une barre discrète en bas de l'écran qui indique les étapes à franchir pour voir
   Zelyro fonctionner (prospects, bien, rapprochement, réception automatique). Disparaît toute seule quand
   tout est fait, ou quand on la masque. Aucune donnée n'est envoyée ailleurs qu'à l'API de l'agence. */
(function () {
    var API_URL = 'https://saas-immobilier-921a.onrender.com';
    var CLE_MASQUE = 'zelyro_accueil_masque';
    var token, user;
    try {
        token = localStorage.getItem('token');
        user = JSON.parse(localStorage.getItem('user') || '{}');
        if (!token || localStorage.getItem(CLE_MASQUE) === '1' || (user && user.role === 'employe')) return;
    } catch (e) { return; }

    function appel(chemin) {
        return fetch(API_URL + chemin, { headers: { 'Authorization': 'Bearer ' + token } })
            .then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
    }

    Promise.all([appel('/api/v1/plan'), appel('/api/v1/gmail/status')]).then(function (res) {
        var plan = res[0], gmail = res[1];
        if (!plan || !plan.usage) return;
        var prospects = plan.usage.leads || 0, biens = plan.usage.properties || 0;
        var etapes = [
            { fait: prospects > 0, texte: 'Ajouter vos prospects', lien: '/import.html' },
            { fait: biens > 0, texte: 'Ajouter un bien (avec code postal et ville)', lien: '/biens.html' },
            { fait: prospects > 0 && biens > 0 && localStorage.getItem('zelyro_accueil_matching') === '1',
              texte: 'Voir à qui proposer vos biens', lien: '/matching.html' },
            { fait: !!(gmail && gmail.connected), texte: 'Recevoir vos demandes automatiquement', lien: '/compte.html#gmail' }
        ];
        if (/\/matching\.html$/.test(location.pathname) && prospects > 0 && biens > 0) {
            try { localStorage.setItem('zelyro_accueil_matching', '1'); } catch (e) { /* ignoré */ }
            etapes[2].fait = true;
        }
        var restantes = etapes.filter(function (e) { return !e.fait; });
        if (restantes.length === 0) return;
        var prochaine = restantes[0];
        var faites = etapes.length - restantes.length;

        var barre = document.createElement('div');
        barre.setAttribute('role', 'region');
        barre.setAttribute('aria-label', 'Premiers pas avec Zelyro');
        barre.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:50;background:#F6F2EA;color:#2b2b2b;' +
            'border-top:1px solid #d9d2c3;padding:10px 16px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;' +
            'justify-content:space-between;font:14px/1.4 system-ui,sans-serif;box-shadow:0 -2px 8px rgba(0,0,0,.06)';
        var texte = document.createElement('span');
        texte.textContent = 'Premiers pas : ' + faites + ' étape' + (faites > 1 ? 's' : '') + ' sur ' + etapes.length + '. Prochaine : ' + prochaine.texte + '.';
        var actions = document.createElement('span');
        actions.style.cssText = 'display:flex;gap:8px;align-items:center';
        var aller = document.createElement('a');
        aller.href = prochaine.lien;
        aller.textContent = 'Continuer';
        aller.style.cssText = 'background:#4F6353;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;min-height:20px';
        var masquer = document.createElement('button');
        masquer.type = 'button';
        masquer.textContent = 'Masquer';
        masquer.style.cssText = 'background:none;border:1px solid #bdb6a6;border-radius:8px;padding:10px 14px;cursor:pointer;color:inherit;font:inherit';
        masquer.onclick = function () {
            try { localStorage.setItem(CLE_MASQUE, '1'); } catch (e) { /* ignoré */ }
            barre.remove();
            document.body.style.paddingBottom = '';
        };
        actions.appendChild(aller);
        actions.appendChild(masquer);
        barre.appendChild(texte);
        barre.appendChild(actions);
        document.body.appendChild(barre);
        document.body.style.paddingBottom = '72px';   // la barre ne doit pas cacher le bas de la page
    });
})();
