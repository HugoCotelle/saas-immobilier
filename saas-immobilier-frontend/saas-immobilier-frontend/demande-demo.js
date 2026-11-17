/* Formulaire de demande de démonstration de la page d'atterrissage (demo-agences.html).

   Garanties :
   - une demande n'est annoncée « envoyée » que si le serveur répond qu'elle est ENREGISTRÉE (HTTP 200) ;
   - un identifiant unique est créé à l'ouverture de la page et réutilisé à chaque nouvel essai : un double clic,
     un retour en arrière ou une nouvelle tentative après une coupure ne créent jamais deux demandes ;
   - la page de confirmation (/demo-merci.html) ne mesure la demande dans Google Ads et dans le Pixel Meta que si le
     serveur a confirmé une NOUVELLE demande (drapeau posé ici) ; une demande déjà connue (doublon) n'est pas recomptée ;
   - ce que le visiteur écrit n'est jamais envoyé à un service publicitaire ni au suivi du parcours. */
(function () {
    'use strict';
    var API_URL = 'https://saas-immobilier-921a.onrender.com';
    var page = document.getElementById('demande-demo-form');
    if (!page) return;

    var DELAI_MS = 45000;      // le serveur gratuit peut mettre du temps à se réveiller
    var FONCTIONS = [['', 'Choisir…'], ['dirigeant', 'Dirigeant ou gérant'], ['directeur', 'Directeur d’agence'],
        ['responsable', 'Responsable d’équipe'], ['negociateur', 'Négociateur'], ['autre', 'Autre']];

    function suivi(e, d) { try { if (window.zelyroSuivi) window.zelyroSuivi(e, d); } catch (x) { /* ignoré */ } }

    function el(tag, attrs, enfants) {
        var n = document.createElement(tag);
        Object.keys(attrs || {}).forEach(function (k) {
            if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
        });
        (enfants || []).forEach(function (e) { n.appendChild(e); });
        return n;
    }
    function groupe(id, libelle, facultatif, contenu) {
        var l = el('label', { 'for': 'dd-' + id });
        l.appendChild(document.createTextNode(libelle));
        if (facultatif) l.appendChild(el('span', { 'class': 'dd-facultatif', text: ' (facultatif)' }));
        return el('div', { 'class': 'dd-champ', 'data-champ': id }, [l, contenu]);
    }
    function saisie(id, libelle, type, facultatif, extra) {
        var a = Object.assign({ id: 'dd-' + id, name: id, type: type, maxlength: '255' }, extra || {});
        if (!facultatif) { a.required = ''; a['aria-required'] = 'true'; }
        return groupe(id, libelle, facultatif, el('input', a));
    }
    function liste(id, libelle, options) {
        var s = el('select', { id: 'dd-' + id, name: id, required: '', 'aria-required': 'true' });
        options.forEach(function (o) { s.appendChild(el('option', { value: o[0], text: o[1] })); });
        return groupe(id, libelle, false, s);
    }

    function identifiant() {
        var id = '';
        try {
            var oct = new Uint8Array(12);
            crypto.getRandomValues(oct);
            for (var i = 0; i < oct.length; i++) id += (oct[i] < 16 ? '0' : '') + oct[i].toString(16);
        } catch (e) { id = ''; }
        if (!/^[0-9a-f]{24}$/.test(id)) {      // repli : 24 caractères hexadécimaux quand même, le serveur les exige
            for (var j = 0; j < 24; j++) id += Math.floor(Math.random() * 16).toString(16);
        }
        return id;
    }

    // D'où vient le visiteur : lu dans l'adresse de la page (jamais dans un cookie). Aucune donnée saisie n'y figure.
    function provenance() {
        var o = {};
        try {
            var q = new URLSearchParams(location.search);
            ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'].forEach(function (k) {
                var v = q.get(k);
                if (v) o[k] = String(v).slice(0, 120);
            });
            if (q.get('fbclid')) o.clic_pub = 'meta';
            else if (q.get('gclid') || q.get('gbraid') || q.get('wbraid')) o.clic_pub = 'google';
            else if (q.get('cp') === 'meta' || q.get('cp') === 'google') o.clic_pub = q.get('cp');      // reporté par stats.js depuis la page précédente
            var rh = q.get('rh');       // nom de domaine seul du site d'origine, reporté par stats.js (jamais un chemin)
            if (rh && /^[a-z0-9.-]{1,120}$/i.test(rh)) o.referent_origine = rh.toLowerCase();
        } catch (e) { /* navigateur ancien */ }
        try { if (document.referrer) o.referent = document.referrer.slice(0, 300); } catch (e) { /* ignoré */ }
        return o;
    }

    function batir(surSucces) {
        var enCours = false, debute = false;
        var idDemande = identifiant();
        var f = el('form', { 'class': 'dd-form', novalidate: '', id: 'dd-form' });
        f.appendChild(saisie('nom', 'Prénom et nom', 'text', false, { autocomplete: 'name', maxlength: '100' }));
        f.appendChild(saisie('email', 'E-mail professionnel', 'email', false, { autocomplete: 'email', inputmode: 'email', autocapitalize: 'none', spellcheck: 'false' }));
        f.appendChild(saisie('agence', 'Nom de l’agence', 'text', false, { autocomplete: 'organization', maxlength: '120' }));
        f.appendChild(liste('fonction', 'Votre fonction', FONCTIONS));
        f.appendChild(saisie('telephone', 'Téléphone', 'tel', true, { autocomplete: 'tel', inputmode: 'tel', maxlength: '30' }));
        // Champ piège : invisible pour une personne, rempli par les robots.
        f.appendChild(el('div', { 'class': 'dd-piege', 'aria-hidden': 'true' }, [
            el('label', { 'for': 'dd-site_web', text: 'Ne pas remplir' }),
            el('input', { id: 'dd-site_web', name: 'site_web', type: 'text', tabindex: '-1', autocomplete: 'off' })
        ]));
        var retour = el('p', { 'class': 'dd-retour', role: 'alert', 'aria-live': 'assertive' });
        var bouton = el('button', { type: 'submit', 'class': 'btn btn-lg', text: 'Demander ma démonstration' });
        f.appendChild(retour);
        f.appendChild(el('div', { 'class': 'dd-actions' }, [bouton]));
        f.appendChild(el('p', { 'class': 'dd-garantie', text: 'Démonstration gratuite de 20 minutes, sans engagement.' }));
        f.appendChild(el('p', { 'class': 'dd-mention' }, [
            document.createTextNode('Zelyro SAS, responsable du traitement, utilise ces informations pour répondre à votre demande et vous recontacter, '
                + 'y compris par e-mail, au sujet de nos offres (intérêt légitime). La campagne publicitaire dont vous venez, s’il y en a une, est notée. '
                + 'Elles sont conservées 3 ans après notre dernier échange. Vous pouvez vous opposer à ce traitement, accéder à vos données ou les faire effacer : '),
            el('a', { href: 'mailto:contact@zelyro.fr', text: 'contact@zelyro.fr' }),
            document.createTextNode('. '),
            el('a', { href: '/confidentialite.html', text: 'Politique de confidentialité' })
        ]));

        function message(texte, erreur) {
            retour.textContent = texte;
            retour.className = 'dd-retour' + (erreur ? ' dd-erreur' : '');
        }
        function marquer(nom) {
            Array.prototype.forEach.call(f.elements, function (c) { if (c.name) c.removeAttribute('aria-invalid'); });
            if (nom && f.elements[nom]) f.elements[nom].setAttribute('aria-invalid', 'true');
        }
        function valider(d) {
            if (d.nom.trim().length < 2) return ['nom', 'Indiquez votre nom.'];
            if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.email.trim())) return ['email', 'Indiquez une adresse e-mail valide.'];
            if (d.agence.trim().length < 2) return ['agence', 'Indiquez le nom de votre agence.'];
            if (!d.fonction) return ['fonction', 'Choisissez votre fonction.'];
            if (d.telephone.trim() && d.telephone.replace(/\D/g, '').length < 8) return ['telephone', 'Ce numéro de téléphone semble incomplet.'];
            return null;
        }
        function echec(nom, texte, champ) {
            marquer(champ || null);
            message(texte, true);
            suivi('formulaire_erreur', nom);      // seulement le NOM du champ ou du problème, jamais la valeur saisie
        }

        f.addEventListener('focusin', function (e) {
            if (!debute && e.target && e.target.name && e.target.name !== 'site_web') { debute = true; suivi('formulaire_debut', 'demo'); }
        });
        f.addEventListener('input', function () { if (!enCours) { message('', false); marquer(null); } });
        f.addEventListener('submit', function (e) {
            e.preventDefault();
            if (enCours) return;                     // double clic ou touche Entrée répétée
            var d = {};
            ['nom', 'email', 'agence', 'fonction', 'telephone', 'site_web'].forEach(function (k) { d[k] = f.elements[k].value; });
            var probleme = valider(d);
            if (probleme) { echec(probleme[0], probleme[1], probleme[0]); f.elements[probleme[0]].focus(); return; }
            var corps = Object.assign({}, d, provenance(), { id_demande: idDemande, page: location.pathname, w: window.innerWidth || 0 });
            enCours = true;
            bouton.disabled = true;
            bouton.textContent = 'Envoi…';
            message('', false);
            marquer(null);
            var ctrl = window.AbortController ? new AbortController() : null;
            var minuteur = ctrl ? setTimeout(function () { ctrl.abort(); }, DELAI_MS) : null;
            var termine = false;
            fetch(API_URL + '/api/v1/demande-demo', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(corps),
                signal: ctrl ? ctrl.signal : undefined
            }).then(function (r) {
                return r.json().catch(function () { return {}; }).then(function (c) { return { ok: r.ok, status: r.status, corps: c }; });
            }).then(function (r) {
                if (r.ok) { termine = true; surSucces(r.corps || {}, idDemande); return; }
                if (r.status === 429) echec('limite', 'Vous avez déjà envoyé une demande. Nous revenons vers vous très vite, ou écrivez-nous à contact@zelyro.fr.');
                else if (r.status >= 500) echec('serveur', (r.corps && r.corps.message) || 'Votre demande n’a pas pu être enregistrée. Écrivez-nous à contact@zelyro.fr.');
                else echec('refus', (r.corps && r.corps.message) || 'Votre demande n’a pas pu être envoyée. Vérifiez les champs ou écrivez-nous à contact@zelyro.fr.');
            }).catch(function (err) {
                if (err && err.name === 'AbortError') echec('delai', 'Le serveur met trop de temps à répondre. Vous pouvez réessayer : votre demande ne sera pas enregistrée deux fois.');
                else echec('reseau', 'Connexion impossible. Réessayez dans un instant, ou écrivez-nous à contact@zelyro.fr.');
            }).then(function () {
                if (minuteur) clearTimeout(minuteur);
                if (termine) return;                 // la page va changer : le bouton reste bloqué, aucun second envoi possible
                enCours = false;
                bouton.disabled = false;
                bouton.textContent = 'Demander ma démonstration';
            });
        });
        return f;
    }

    page.appendChild(batir(function (reponse, id) {
        // Le serveur a ENREGISTRÉ la demande (HTTP 200). Le drapeau « nouvelle demande » ne sert qu'à mesurer une fois
        // dans Google Ads / Meta : pas de drapeau pour un doublon (même personne déjà enregistrée) ni pour un robot.
        var ref = reponse && /^[0-9a-f]{24}$/.test(reponse.ref || '') ? reponse.ref : '';
        if (ref && reponse.doublon !== true) {
            try { sessionStorage.setItem('zelyro_demande_ok', ref); } catch (e) { /* ignoré */ }
        }
        location.href = '/demo-merci.html';
    }));
})();
