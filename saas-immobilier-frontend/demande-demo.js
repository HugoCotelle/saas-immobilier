/* Formulaire de demande de démonstration : s'ouvre dans une fenêtre depuis tout lien portant data-demo.
   Les liens gardent un mailto: de secours, utilisé seulement si ce script ne peut pas s'exécuter. */
(function () {
    'use strict';
    var API_URL = 'https://saas-immobilier-921a.onrender.com';
    var liens = document.querySelectorAll('a[data-demo]');
    if (!liens.length || typeof HTMLDialogElement === 'undefined') return;

    var dialogue = null, formulaire = null, retour = null, bouton = null, enCours = false, declencheur = null;

    function el(tag, attrs, enfants) {
        var n = document.createElement(tag);
        Object.keys(attrs || {}).forEach(function (k) {
            if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
        });
        (enfants || []).forEach(function (e) { n.appendChild(e); });
        return n;
    }
    function groupe(c, contenu) {
        var l = el('label', { 'for': 'dd-' + c.id });
        l.appendChild(document.createTextNode(c.libelle));
        if (!c.obligatoire) l.appendChild(el('span', { 'class': 'dd-facultatif', text: ' (facultatif)' }));
        return el('div', { 'class': 'dd-champ' }, [l, contenu]);
    }
    function saisie(id, libelle, type, obligatoire, extra) {
        var a = Object.assign({ id: 'dd-' + id, name: id, type: type, maxlength: '255' }, extra || {});
        if (obligatoire) { a.required = ''; a['aria-required'] = 'true'; }
        return groupe({ id: id, libelle: libelle, obligatoire: obligatoire }, el('input', a));
    }
    function liste(id, libelle, options) {
        var s = el('select', { id: 'dd-' + id, name: id });
        options.forEach(function (o) { s.appendChild(el('option', { value: o[0], text: o[1] })); });
        return groupe({ id: id, libelle: libelle, obligatoire: false }, s);
    }

    function construire() {
        formulaire = el('form', { 'class': 'dd-form', novalidate: '' });
        formulaire.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('nom', 'Votre nom', 'text', true, { autocomplete: 'name', maxlength: '100' }),
            saisie('email', 'E-mail professionnel', 'email', true, { autocomplete: 'email' })
        ]));
        formulaire.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('agence', 'Nom de l’agence', 'text', true, { autocomplete: 'organization', maxlength: '120' }),
            saisie('ville', 'Ville', 'text', false, { autocomplete: 'address-level2', maxlength: '80' })
        ]));
        formulaire.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('telephone', 'Téléphone', 'tel', false, { autocomplete: 'tel', maxlength: '30' }),
            liste('taille', 'Taille de l’équipe', [['', 'Choisir…'], ['1', '1 personne'], ['2-5', '2 à 5 personnes'],
                ['6-15', '6 à 15 personnes'], ['16+', '16 personnes et plus']])
        ]));
        formulaire.appendChild(el('div', { 'class': 'dd-ligne' }, [
            saisie('outil', 'Outil utilisé aujourd’hui', 'text', false, { maxlength: '80', placeholder: 'Ubiflow, Hektor, Excel…' }),
            liste('creneau', 'Créneau souhaité', [['', 'Choisir…'], ['matin', 'Plutôt le matin'],
                ['apres-midi', 'Plutôt l’après-midi'], ['indifferent', 'Indifférent']])
        ]));
        formulaire.appendChild(groupe({ id: 'message', libelle: 'Message', obligatoire: false },
            el('textarea', { id: 'dd-message', name: 'message', rows: '3', maxlength: '1500' })));
        // Champ piège : invisible pour une personne, rempli par les robots.
        formulaire.appendChild(el('div', { 'class': 'dd-piege', 'aria-hidden': 'true' }, [
            el('label', { 'for': 'dd-site_web', text: 'Ne pas remplir' }),
            el('input', { id: 'dd-site_web', name: 'site_web', type: 'text', tabindex: '-1', autocomplete: 'off' })
        ]));
        retour = el('p', { 'class': 'dd-retour', role: 'alert', 'aria-live': 'assertive' });
        bouton = el('button', { type: 'submit', 'class': 'btn btn-lg', text: 'Envoyer ma demande' });
        formulaire.appendChild(retour);
        formulaire.appendChild(el('div', { 'class': 'dd-actions' }, [bouton]));
        formulaire.appendChild(el('p', { 'class': 'dd-mention' }, [
            document.createTextNode('Vos informations servent uniquement à vous répondre. '),
            el('a', { href: '/confidentialite.html', text: 'Politique de confidentialité' })
        ]));
        formulaire.addEventListener('submit', envoyer);
        formulaire.addEventListener('input', function () { if (!enCours) message('', false); });

        var fermer = el('button', { type: 'button', 'class': 'dd-fermer', 'aria-label': 'Fermer', text: '×' });
        fermer.addEventListener('click', function () { dialogue.close(); });
        dialogue = el('dialog', { 'class': 'dd-dialogue', 'aria-labelledby': 'dd-titre' }, [
            fermer,
            el('h2', { id: 'dd-titre', text: 'Demander une démonstration' }),
            el('p', { 'class': 'dd-intro', text: 'Quelques informations, et nous revenons vers vous très vite pour convenir d’un créneau.' }),
            formulaire
        ]);
        dialogue.addEventListener('click', function (e) { if (e.target === dialogue) dialogue.close(); });
        dialogue.addEventListener('close', function () {
            if (declencheur && declencheur.focus) declencheur.focus();
        });
        document.body.appendChild(dialogue);
    }

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

    function envoyer(e) {
        e.preventDefault();
        if (enCours) return;
        var d = {};
        ['nom', 'email', 'agence', 'ville', 'telephone', 'taille', 'outil', 'creneau', 'message', 'site_web'].forEach(function (k) {
            d[k] = formulaire.elements[k].value;
        });
        var probleme = valider(d);
        if (probleme) {
            message(probleme[1], true);
            formulaire.elements[probleme[0]].focus();
            return;
        }
        enCours = true;
        bouton.disabled = true;
        bouton.textContent = 'Envoi…';
        message('', false);
        fetch(API_URL + '/api/v1/demande-demo', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(d)
        }).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (corps) { return { ok: r.ok, status: r.status, corps: corps }; });
        }).then(function (r) {
            if (r.ok) { merci(d.nom.trim().split(/\s+/)[0]); return; }
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
    }

    function merci(prenom) {
        var ok = el('div', { 'class': 'dd-merci', role: 'status' }, [
            el('h3', { text: 'Merci ' + prenom + ', votre demande est bien partie.' }),
            el('p', { text: 'Un e-mail de confirmation vient de vous être envoyé. Nous vous répondons très vite pour convenir d’un créneau.' }),
        ]);
        var fin = el('button', { type: 'button', 'class': 'btn btn-ghost', text: 'Fermer' });
        fin.addEventListener('click', function () { dialogue.close(); });
        ok.appendChild(fin);
        formulaire.replaceWith(ok);
        dialogue.querySelector('.dd-intro').hidden = true;
        ok.setAttribute('tabindex', '-1');
        ok.focus();
        formulaire = null;
    }

    function ouvrir(e) {
        e.preventDefault();
        declencheur = e.currentTarget;
        if (!dialogue || !formulaire) {
            if (dialogue) dialogue.remove();
            construire();
        }
        message('', false);
        if (!dialogue.open) dialogue.showModal();
        var premier = formulaire.elements.nom;
        if (premier) premier.focus();
    }

    Array.prototype.forEach.call(liens, function (a) { a.addEventListener('click', ouvrir); });
    if (location.hash === '#demande-demo') ouvrir({ preventDefault: function () {}, currentTarget: liens[0] });
})();
