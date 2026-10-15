/* Petite blague entre associés : un message plein écran, uniquement pour le compte d'Hugo,
   pendant 24 h après sa première apparition (et jamais après la date butoir ci-dessous).
   Une fois la blague finie, il suffit de supprimer ce fichier et la ligne <script src="/blague.js">
   de taches.html : elle s'éteint d'ailleurs d'elle-même. */
(function () {
    var CIBLE = 'hc@zelyro.fr';
    var DUREE_MS = 24 * 3600 * 1000;
    var DATE_BUTOIR = Date.UTC(2026, 9, 22);           // 22 octobre 2026 : coupe-circuit
    try {
        if (Date.now() > DATE_BUTOIR) return;
        var user = JSON.parse(localStorage.getItem('user') || 'null');
        if (!user || String(user.email || '').trim().toLowerCase() !== CIBLE) return;
        if (sessionStorage.getItem('zl_blague_vue')) return;     // une fois par connexion
        var premiere = parseInt(localStorage.getItem('zl_blague_debut') || '0', 10);
        if (!premiere) { premiere = Date.now(); localStorage.setItem('zl_blague_debut', String(premiere)); }
        if (Date.now() - premiere > DUREE_MS) return;
        sessionStorage.setItem('zl_blague_vue', '1');
    } catch (e) { return; }

    function afficher() {
        var fond = document.createElement('div');
        fond.setAttribute('role', 'dialog');
        fond.setAttribute('aria-label', 'Message de Tom');
        fond.style.cssText = 'position:fixed;inset:0;z-index:99999;background:#F6F2EA;display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:pointer;overflow:hidden';

        var titre = document.createElement('div');
        titre.style.cssText = "font-family:'Playfair Display',Georgia,serif;font-weight:800;line-height:1;text-align:center;font-size:17vw;color:#1F2A24;letter-spacing:-0.02em;padding:0 4vw";
        titre.appendChild(document.createTextNode('Hugo '));
        var rouge = document.createElement('em');
        rouge.style.cssText = 'display:block;color:#E5484D;font-style:italic';
        rouge.textContent = 'la salope';
        titre.appendChild(rouge);
        fond.appendChild(titre);

        var signature = document.createElement('div');
        signature.style.cssText = 'position:absolute;bottom:56px;left:0;right:0;text-align:center;font:14px Inter,system-ui,sans-serif;color:#6A7168';
        signature.textContent = 'Un petit message de Tom, pour rire. Cliquez n’importe où pour continuer à travailler.';
        fond.appendChild(signature);

        var fermer = document.createElement('button');
        fermer.type = 'button';
        fermer.textContent = 'Fermer';
        fermer.style.cssText = 'position:absolute;top:18px;right:18px;padding:9px 18px;border-radius:999px;border:1px solid #D2C9B4;background:#FFFDF9;color:#1F2A24;font:600 14px Inter,system-ui,sans-serif;cursor:pointer';
        fond.appendChild(fermer);

        function fin() { if (fond.parentNode) fond.parentNode.removeChild(fond); document.removeEventListener('keydown', touche); }
        function touche(e) { if (e.key === 'Escape') fin(); }
        fond.addEventListener('click', fin);
        document.addEventListener('keydown', touche);

        document.body.appendChild(fond);
        if (titre.animate) {
            titre.animate([{ transform: 'scale(1) rotate(-1deg)' }, { transform: 'scale(1.05) rotate(1deg)' }, { transform: 'scale(1) rotate(-1deg)' }],
                          { duration: 1600, iterations: Infinity, easing: 'ease-in-out' });
        }
    }

    if (document.body) afficher();
    else document.addEventListener('DOMContentLoaded', afficher);
})();
