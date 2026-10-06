/*
 * Identité de l'éditeur : un seul endroit à remplir pour les quatre pages juridiques
 * (mentions légales, CGU, politique de confidentialité, accord de sous-traitance).
 *
 * Remplissez les valeurs entre guillemets ci-dessous, enregistrez, déployez : tous les
 * passages surlignés en jaune correspondants disparaissent. Un champ laissé vide
 * garde son repère jaune « À COMPLÉTER » sur les pages.
 */
(function () {
    var SOCIETE = {
        adresse: '59 rue de Ponthieu, bureau 326, 75008 Paris',          // ex. '12 rue de la Paix, 75002 Paris'
        siren: '',            // 9 chiffres, ex. '123 456 789'
        rcs_ville: 'Paris',        // ville du greffe, ex. 'Paris'
        capital: '1 000 €',          // ex. '1 000 €'
        tva: '',              // ex. 'FR12 123456789'
        telephone: '',        // ex. '01 23 45 67 89'
        directeur: 'Hugo Cotelle, Président',        // ex. 'Prénom Nom, Président'
        tribunal_ville: 'Paris',   // ville du tribunal de commerce du siège, ex. 'Paris'
        date_maj: '6 octobre 2026'
    };

    // Un SIREN comporte 9 chiffres et respecte la clé de Luhn : on prévient dans la console si une faute de frappe est probable.
    function sirenValide(s) {
        var c = String(s).replace(/\s/g, '');
        if (!/^\d{9}$/.test(c)) return false;
        var somme = 0;
        for (var i = 0; i < 9; i++) {
            var n = parseInt(c.charAt(8 - i), 10);
            if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
            somme += n;
        }
        return somme % 10 === 0;
    }

    function formater(cle, valeur) {
        if (cle === 'siren') {
            var c = valeur.replace(/\s/g, '');
            if (/^\d{9}$/.test(c)) return c.replace(/(\d{3})(\d{3})(\d{3})/, '$1 $2 $3');
        }
        return valeur;
    }

    function remplir() {
        if (SOCIETE.siren && !sirenValide(SOCIETE.siren) && window.console) {
            console.warn('societe.js : le SIREN saisi ne semble pas valide (9 chiffres, clé de contrôle). Vérifiez-le.');
        }
        var champs = document.querySelectorAll('[data-societe]');
        for (var i = 0; i < champs.length; i++) {
            var cle = champs[i].getAttribute('data-societe');
            var valeur = SOCIETE[cle];
            if (typeof valeur === 'string' && valeur.replace(/\s/g, '') !== '') {
                champs[i].textContent = formater(cle, valeur.trim());
                champs[i].classList.remove('a-completer');
            }
        }
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', remplir);
    else remplir();
})();
