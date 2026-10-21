/* Formulaire de demande de démonstration de la page d'atterrissage (demo-agences.html).
   Une fois la demande envoyée, le visiteur est conduit sur /demo-merci.html : c'est cette page qui sert de repère
   pour mesurer les demandes dans Google Ads. */
(function () {
    'use strict';
    var API_URL = 'https://saas-immobilier-921a.onrender.com';
    var page = document.getElementById('demande-demo-form');
    if (!page) return;

    function el(tag, attrs, enfants) {
        var n = document.createElement(tag);
        Object.keys(attrs || {}).forEach(function (k) {
            if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
        });
        (enfants || []).forEach(function (e) { n.appendChild(e); });
        return n;
    }
    function groupe(id, libelle, obligatoire, contenu) {
        var l = el('label', { 'for': 'dd-' + id });
        l.appendChild(document.createTextNode(libelle));
        if (!obligatoire) l.appendChild(el('span', { 'class': 'dd-facultatif', text: ' (facultatif)' }));
        return el('div', { 'class': 'dd-champ' }, [l, contenu]);
    }
    function saisie(id, libelle, type, obligatoire, extra) {
        var a = Object.assign({ id: 'dd-' + id, name: id, type: type, maxlength: '255' }, extra || {});
        if (obligatoire) { a.required = ''; a['aria-required'] = 'true'; }
        return groupe(id, libelle, obligatoire, el('input', a));
    }
    function liste(id, libelle, options) {
        var s = el('select', { id: 'dd-' + id, name: id });
        options.forEach(function (o) { s.appendChild(el('option', { value: o[0], text: o[1] })); });
        return groupe(id, libelle, false, s);
    }

    // D'où vient le visiteur (annonce Google Ads, newsletter…) : lu dans l'adresse de la page, jamais dans un cookie.
    function origine() {
        try {
            var q = new URLSearchParams(location.search), p = [];
            if (q.get('utm_source')) p.push(q.get('utm_source') + (q.get('utm_medium') ? ' / ' + q.get('utm_medium') : ''));
            else if (q.get('gclid')) p.push('Google Ads');
            if (q.get('utm_campaign')) p.push('campagne ' + q.get('utm_campaign'));
            if (q.get('utm_term')) p.push('mot-clé ' + q.get('utm_term'));
            return p.join(', ').slice(0, 200);
        } catch (e) { return ''; }
    }

    /* Construit un formulaire ; surSucces(prenom) est appelé quand la demande est partie. */
    function batir(surSucces) {
        var enCours = false;
        var f = el('form', { 'class': 'dd-form', novalidate: '' });
        f.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('nom', 'Votre nom', 'text', true, { autocomplete: 'name', maxlength: '100' }),
            saisie('email', 'E-mail professionnel', 'email', true, { autocomplete: 'email' })
        ]));
        f.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('agence', 'Nom de l’agence', 'text', true, { autocomplete: 'organization', maxlength: '120' }),
            saisie('ville', 'Ville', 'text', false, { autocomplete: 'address-level2', maxlength: '80' })
        ]));
        f.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('telephone', 'Téléphone', 'tel', false, { autocomplete: 'tel', maxlength: '30' }),
            liste('taille', 'Taille de l’équipe', [['', 'Choisir…'], ['1', '1 personne'], ['2-5', '2 à 5 personnes'],
                ['6-15', '6 à 15 personnes'], ['16+', '16 personnes et plus']])
        ]));
        f.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('outil', 'Outil utilisé aujourd’hui', 'text', false, { maxlength: '80', placeholder: 'Ubiflow, Hektor, Excel…' }),
            liste('creneau', 'Créneau souhaité', [['', 'Choisir…'], ['matin', 'Plutôt le matin'],
                ['apres-midi', 'Plutôt l’après-midi'], ['indifferent', 'Indifférent']])
        ]));
        f.appendChild(groupe('message', 'Message', false,
            el('textarea', { id: 'dd-message', name: 'message', rows: '3', maxlength: '1500' })));
        // Champ piège : invisible pour une personne, rempli par les robots.
        f.appendChild(el('div', { 'class': 'dd-piege', 'aria-hidden': 'true' }, [
            el('label', { 'for': 'dd-site_web', text: 'Ne pas remplir' }),
            el('input', { id: 'dd-site_web', name: 'site_web', type: 'text', tabindex: '-1', autocomplete: 'off' })
        ]));
        var retour = el('p', { 'class': 'dd-retour', role: 'alert', 'aria-live': 'assertive' });
        var bouton = el('button', { type: 'submit', 'class': 'btn btn-lg', text: 'Envoyer ma demande' });
        f.appendChild(retour);
        f.appendChild(el('div', { 'class': 'dd-actions' }, [bouton]));
        f.appendChild(el('p', { 'class': 'dd-mention' }, [
            document.createTextNode('Zelyro SAS, responsable du traitement, utilise ces informations pour répondre à votre demande de démonstration et vous recontacter, '
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
        function valider(d) {
            if (d.nom.trim().length < 2) return ['nom', 'Indiquez votre nom.'];
            if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.email.trim())) return ['email', 'Indiquez une adresse e-mail valide.'];
            if (d.agence.trim().length < 2) return ['agence', 'Indiquez le nom de votre agence.'];
            if (d.telephone.trim() && d.telephone.replace(/\D/g, '').length < 8) return ['telephone', 'Ce numéro de téléphone semble incomplet.'];
            return null;
        }
        f.addEventListener('input', function () { if (!enCours) message('', false); });
        f.addEventListener('submit', function (e) {
            e.preventDefault();
            if (enCours) return;
            var d = {};
            ['nom', 'email', 'agence', 'ville', 'telephone', 'taille', 'outil', 'creneau', 'message', 'site_web'].forEach(function (k) {
                d[k] = f.elements[k].value;
            });
            d.origine = origine();
            var probleme = valider(d);
            if (probleme) { message(probleme[1], true); f.elements[probleme[0]].focus(); return; }
            enCours = true;
            bouton.disabled = true;
            bouton.textContent = 'Envoi…';
            message('', false);
            fetch(API_URL + '/api/v1/demande-demo', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d)
            }).then(function (r) {
                return r.json().catch(function () { return {}; }).then(function (corps) { return { ok: r.ok, status: r.status, corps: corps }; });
            }).then(function (r) {
                if (r.ok) { surSucces(d.nom.trim().split(/\s+/)[0], f); return; }
                message(r.status === 429
                    ? 'Vous avez déjà envoyé une demande. Nous revenons vers vous très vite, ou écrivez-nous à contact@zelyro.fr.'
                    : (r.corps.message || 'Votre demande n’a pas pu être envoyée. Écrivez-nous à contact@zelyro.fr.'), true);
            }).catch(function () {
                message('Connexion impossible. Réessayez dans un instant, ou écrivez-nous à contact@zelyro.fr.', true);
            }).then(function () {
                enCours = false;
                bouton.disabled = false;
                bouton.textContent = 'Envoyer ma demande';
            });
        });
        return f;
    }

    // ----- Page d'atterrissage : formulaire intégré à la page -----
    if (page) {
        page.appendChild(batir(function () { location.href = '/demo-merci.html'; }));
    }

})();
