/* Zelyro — page d'accueil : interactions.
   Tout se passe dans la page : aucune donnée n'est envoyée (la mesure d'audience est dans stats.js).
   Les scores affichés suivent les règles de calcul de l'application (app.py : points_qualite et
   _detail_score_base) ; les prospects et les biens sont fictifs. */
(function () {
    'use strict';
    var doc = document, root = doc.documentElement;
    root.classList.add('anim');
    var reduit = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    var finPointeur = !!(window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches);
    var $ = function (s, c) { return (c || doc).querySelector(s); };
    var $$ = function (s, c) { return Array.prototype.slice.call((c || doc).querySelectorAll(s)); };
    function nf(n, d) {
        return Number(n).toLocaleString('fr-FR', { maximumFractionDigits: d || 0, minimumFractionDigits: 0 }).replace(/[  ]/g, ' ');
    }
    function euros(n) { return nf(Math.round(n), 0) + ' €'; }
    function esc(t) { return String(t).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
    function compteur(el, de, a, duree, fmt) {
        fmt = fmt || function (v) { return nf(Math.round(v)); };
        if (reduit || !el) { if (el) el.textContent = fmt(a); return; }
        var t0 = null; duree = duree || 700;
        if (el._raf) cancelAnimationFrame(el._raf);
        function pas(t) {
            if (!t0) t0 = t;
            var k = Math.min(1, (t - t0) / duree), e = 1 - Math.pow(1 - k, 3);
            el.textContent = fmt(de + (a - de) * e);
            if (k < 1) el._raf = requestAnimationFrame(pas);
        }
        el._raf = requestAnimationFrame(pas);
    }
    function quandVisible(el, fn, opts) {
        if (!el) return;
        if (!('IntersectionObserver' in window)) { fn(); return; }
        var io = new IntersectionObserver(function (en) {
            en.forEach(function (e) { if (e.isIntersecting) { io.disconnect(); fn(); } });
        }, opts || { threshold: 0.25 });
        io.observe(el);
    }

    /* ---------- Règles de qualification (projet d'achat) ---------- */
    var FIN = { approved: [36, 'Financement approuvé'], in_progress: [22, 'Financement en cours'], pending: [11, 'Financement en attente'] };
    var URG = { immediate: [32, 'Achat immédiat'], '1-3': [25, 'Achat sous 3 mois'], '3-6': [14, 'Achat sous 6 mois'], '6plus': [4, 'Achat au-delà de 6 mois'] };
    var ENG = { formulaire_ouvert: [2, 'A ouvert son formulaire'], formulaire_rempli: [4, 'A rempli son formulaire'], annonces_ouvertes: [3, 'A ouvert les annonces reçues'], interet_bien: [6, 'A demandé une visite'], rdv_confirme: [8, 'A fixé un rendez-vous de visite'] };
    var ORDRE_ENG = ['formulaire_ouvert', 'formulaire_rempli', 'annonces_ouvertes', 'interet_bien', 'rdv_confirme'];
    function qualifier(p) {
        var l = [], cat = { fin: 0, urg: 0, coord: 0, dos: 0, eng: 0 };
        function aj(c, n, t, plafond) { cat[c] += n; l.push({ c: c, n: n, t: t, plafond: !!plafond }); }
        if (FIN[p.fin]) aj('fin', FIN[p.fin][0], FIN[p.fin][1]);
        if (URG[p.urg]) aj('urg', URG[p.urg][0], URG[p.urg][1]);
        if (p.email) aj('coord', 4, 'E-mail renseigné');
        if (p.tel) aj('coord', 4, 'Téléphone renseigné');
        if (p.budget) aj('dos', 5, 'Budget renseigné');
        if (p.secteur) aj('dos', 4, 'Secteur renseigné');
        if (p.type) aj('dos', 3, 'Type de bien renseigné');
        var e = 0;
        ORDRE_ENG.forEach(function (k) { if ((p.eng || []).indexOf(k) >= 0) { aj('eng', ENG[k][0], ENG[k][1]); e += ENG[k][0]; } });
        if (e > 12) aj('eng', 12 - e, 'Plafond de l’engagement (12 points)', true);
        var s = 0; l.forEach(function (x) { s += x.n; });
        s = Math.min(100, s);
        return { score: s, lignes: l, cat: cat };
    }
    function palier(s) { return s >= 90 ? 'go' : s >= 80 ? 'vert' : s >= 65 ? 'jaune' : s >= 45 ? 'orange' : 'gris'; }
    function niveau(s) { return s >= 80 ? 'Acheteur actif' : s >= 45 ? 'Projet en cours' : 'Premier contact'; }
    function criteres(p) {
        var c = [];
        c.push(p.fin === 'approved' || p.fin === 'in_progress' ? [FIN[p.fin][1], 1] : p.fin === 'pending' ? [FIN.pending[1], 0] : ['Financement inconnu', 0]);
        c.push(URG[p.urg] ? [URG[p.urg][1], p.urg !== '6plus'] : ['Échéance inconnue', 0]);
        var manque = [];
        if (!p.budget) manque.push('budget'); if (!p.secteur) manque.push('secteur'); if (!p.type) manque.push('type');
        c.push(!manque.length ? ['Dossier complet', 1] : manque.length === 1 && manque[0] === 'budget' ? ['Budget manquant', 0] : manque.length === 1 && manque[0] === 'secteur' ? ['Secteur manquant', 0] : ['Dossier incomplet', 0]);
        return c;
    }
    var COUL = { fin: 'qc-fin', urg: 'qc-urg', coord: 'qc-coord', dos: 'qc-dos', eng: 'qc-eng' };

    /* ---------- Barre du haut : défilement, jauge, menu, connexion ---------- */
    (function () {
        var barre = $('#barre'), prog = $('#progression'), jauge = $('#jauge'), jv = $('#jauge-val'), jn = $('#jauge-num'), jt = $('#jauge-txt');
        var dernier = -1, tic = false;
        function maj() {
            tic = false;
            var h = root.scrollHeight - innerHeight, p = h > 0 ? Math.min(1, Math.max(0, scrollY / h)) : 0;
            barre.classList.toggle('defile', scrollY > 8);
            prog.style.setProperty('--p', p.toFixed(4));
            var s = Math.round(p * 100);
            if (s !== dernier) {
                dernier = s;
                jv.style.strokeDashoffset = (94.25 * (1 - p)).toFixed(2);
                jn.textContent = s;
                jn.style.fontSize = s >= 100 ? '8.5px' : '';
                var n = palier(s);
                jauge.setAttribute('data-niveau', n);
                jt.textContent = n === 'go' ? 'À appeler maintenant' : 'Votre visite';
                jauge.setAttribute('aria-label', 'Demander une démo (votre visite : ' + s + ' sur 100)');
            }
        }
        addEventListener('scroll', function () { if (!tic) { tic = true; requestAnimationFrame(maj); } }, { passive: true });
        addEventListener('resize', maj);
        maj();

        try {
            if (localStorage.getItem('token')) {
                var a = $('#nav-login');
                if (a) { a.textContent = 'Accéder à mon espace'; a.setAttribute('href', '/taches.html'); }
                $$('a.logo').forEach(function (l) { l.setAttribute('href', '/taches.html'); l.setAttribute('aria-label', 'Zelyro, mes tâches du jour'); });
            }
        } catch (e) { /* stockage indisponible : on garde « Connexion » */ }

        var b = $('.burger'), n = $('#nav');
        function ouvre(o) { n.classList.toggle('ouvert', o); b.setAttribute('aria-expanded', o ? 'true' : 'false'); b.setAttribute('aria-label', o ? 'Fermer le menu' : 'Ouvrir le menu'); }
        b.addEventListener('click', function () { ouvre(!n.classList.contains('ouvert')); });
        n.addEventListener('click', function (e) { if (e.target.closest('a')) ouvre(false); });
        doc.addEventListener('keydown', function (e) { if (e.key === 'Escape' && n.classList.contains('ouvert')) { ouvre(false); b.focus(); } });

        if ('IntersectionObserver' in window) {
            var liens = $$('.nav a[href^="#"]');
            var io = new IntersectionObserver(function (en) {
                en.forEach(function (e) {
                    liens.forEach(function (l) {
                        if (l.getAttribute('href') === '#' + e.target.id) l.classList.toggle('actif', e.isIntersecting);
                        else if (e.isIntersecting) l.classList.remove('actif');
                    });
                });
            }, { rootMargin: '-45% 0px -50% 0px' });
            liens.forEach(function (l) { var c = doc.getElementById(l.getAttribute('href').slice(1)); if (c) io.observe(c); });
        }
    })();

    /* ---------- Apparitions, lumière, boutons aimantés ---------- */
    (function () {
        var cibles = ['.tete', '.retourne', '.ecran-video', '.grille-r > *', '.e-panneau', '.e-carte', '.s-piste', '.b-carte', '.p-machine', '.p-etapes li', '.p-notes li', '.champ', '.noeud', '.garanties li', '.forfait', '.t-curseur', 'details', '.final-carte', '.q-bloc', '.q-profils'];
        var els = [];
        cibles.forEach(function (s) {
            $$(s).forEach(function (el) {
                if (el.hasAttribute('data-r')) return;
                var i = Array.prototype.indexOf.call(el.parentNode.children, el);
                el.setAttribute('data-r', '');
                el.style.setProperty('--rd', Math.min(i * 0.07, 0.35) + 's');
                els.push(el);
            });
        });
        if (reduit || !('IntersectionObserver' in window)) { els.forEach(function (e) { e.classList.add('vu'); }); return; }
        var io = new IntersectionObserver(function (en) {
            en.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('vu'); io.unobserve(e.target); } });
        }, { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
        els.forEach(function (e) { io.observe(e); });
    })();
    if (finPointeur && !reduit) {
        $$('.ch-sombre, .final-carte').forEach(function (z) {
            z.addEventListener('pointermove', function (e) {
                var r = z.getBoundingClientRect();
                z.style.setProperty('--sx', (e.clientX - r.left) + 'px');
                z.style.setProperty('--sy', (e.clientY - r.top) + 'px');
            });
        });
        $$('.btn-aimant').forEach(function (b) {
            b.addEventListener('pointermove', function (e) {
                var r = b.getBoundingClientRect();
                var x = (e.clientX - r.left - r.width / 2) / r.width, y = (e.clientY - r.top - r.height / 2) / r.height;
                b.style.transform = 'translate(' + (x * 10).toFixed(1) + 'px,' + (y * 8).toFixed(1) + 'px)';
            });
            b.addEventListener('pointerleave', function () { b.style.transform = ''; });
        });
    }

    /* ---------- Éclats (confettis) ---------- */
    function eclats(x, y, couleurs) {
        if (reduit) return;
        var c = doc.createElement('canvas'), dpr = Math.min(2, window.devicePixelRatio || 1);
        c.className = 'eclats'; c.width = innerWidth * dpr; c.height = innerHeight * dpr;
        c.setAttribute('aria-hidden', 'true');
        doc.body.appendChild(c);
        var g = c.getContext('2d'); g.scale(dpr, dpr);
        var ps = [];
        for (var i = 0; i < 90; i++) {
            var a = Math.random() * Math.PI * 2, v = 4 + Math.random() * 9;
            ps.push({ x: x, y: y, vx: Math.cos(a) * v, vy: Math.sin(a) * v - 6, r: 3 + Math.random() * 5, c: couleurs[i % couleurs.length], rot: Math.random() * 6, vr: (Math.random() - .5) * .4, f: Math.random() < .5 });
        }
        var t0 = performance.now();
        (function boucle(t) {
            var k = (t - t0) / 1600;
            g.clearRect(0, 0, innerWidth, innerHeight);
            ps.forEach(function (p) {
                p.vy += .32; p.vx *= .985; p.x += p.vx; p.y += p.vy; p.rot += p.vr;
                g.save(); g.globalAlpha = Math.max(0, 1 - k); g.translate(p.x, p.y); g.rotate(p.rot); g.fillStyle = p.c;
                if (p.f) g.fillRect(-p.r, -p.r / 2, p.r * 2, p.r); else { g.beginPath(); g.arc(0, 0, p.r / 1.4, 0, 7); g.fill(); }
                g.restore();
            });
            if (k < 1) requestAnimationFrame(boucle); else c.remove();
        })(t0);
    }

    /* ---------- Appel final : la pile se trie ---------- */
    (function () {
        var f = $('#final-carte'); if (!f) return;
        if (reduit) { f.classList.add('trie'); return; }
        quandVisible($('.final-pile', f) || f, function () { setTimeout(function () { f.classList.add('trie'); }, 600); }, { threshold: 0.6 });
    })();

    /* ---------- Héros : le tri en direct ---------- */
    (function () {
        var scene = $('#scene'), tableau = $('#tableau'), calc = $('#calcul');
        if (!scene) return;
        var P = {
            camille: { nom: 'Camille R.', src: 'Leboncoin', det: 'Appartement · Lille · 420 000 €', fin: 'approved', urg: 'immediate', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['formulaire_rempli'] },
            sarah: { nom: 'Sarah L.', src: 'SeLoger', det: 'Appartement · Marcq-en-Barœul · 310 000 €', fin: 'approved', urg: '1-3', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['annonces_ouvertes'] },
            julien: { nom: 'Julien M.', src: 'Site de l’agence', det: 'Maison · Marcq-en-Barœul · 560 000 €', fin: 'in_progress', urg: '3-6', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['interet_bien', 'formulaire_rempli'], proprio: 1 },
            paul: { nom: 'Paul R.', src: 'SeLoger', det: 'Maison · Roubaix · budget non renseigné', fin: 'pending', urg: '3-6', email: 1, tel: 1, budget: 0, secteur: 1, type: 1, eng: ['interet_bien', 'annonces_ouvertes'], proprio: 1 },
            sophie: { nom: 'Sophie L.', src: 'Leboncoin', det: 'Appartement · budget et secteur non renseignés', fin: '', urg: '6plus', email: 1, tel: 0, budget: 0, secteur: 0, type: 1, eng: ['formulaire_ouvert'] },
            nadia: { nom: 'Nadia B.', src: 'SeLoger', det: 'Appartement · Lille · 285 000 €', fin: 'approved', urg: 'immediate', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['rdv_confirme'] },
            thomas: { nom: 'Thomas G.', src: 'Leboncoin', det: 'Maison · Tourcoing · 320 000 €', fin: 'in_progress', urg: '1-3', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['annonces_ouvertes'] },
            ines: { nom: 'Inès K.', src: 'Leboncoin', det: 'Appartement · budget et secteur non renseignés', fin: '', urg: '6plus', email: 1, tel: 1, budget: 0, secteur: 0, type: 1, eng: [] },
            marc: { nom: 'Marc V.', src: 'SeLoger', det: 'Maison · Villeneuve-d’Ascq · 410 000 €', fin: 'approved', urg: '1-3', email: 0, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['interet_bien'], proprio: 1 },
            lea: { nom: 'Léa D.', src: 'Site de l’agence', det: 'Appartement · Lille · 230 000 €', fin: 'pending', urg: '3-6', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['formulaire_ouvert'] },
            antoine: { nom: 'Antoine P.', src: 'SeLoger', det: 'Appartement · Lille · 350 000 €', fin: 'approved', urg: 'immediate', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['interet_bien'] }
        };
        Object.keys(P).forEach(function (k) { var q = qualifier(P[k]); P[k].q = q; });
        var file = ['nadia', 'thomas', 'ines', 'marc', 'lea', 'antoine', 'paul', 'sarah', 'sophie', 'julien', 'camille'];
        var iFile = 0, age = 0;
        var cartes = $$('.carte', scene).map(function (el) { return { id: el.getAttribute('data-id'), el: el, age: 0 }; });
        // ordre d'arrivée supposé des fiches de départ (la plus ancienne sort en premier)
        ['paul', 'sarah', 'sophie', 'julien', 'camille'].forEach(function (id) { cartes.forEach(function (c) { if (c.id === id) c.age = ++age; }); });

        function ranger(sansId) {
            var l = cartes.filter(function (c) { return !c.sort && c.id !== sansId; }).sort(function (a, b) { return P[b.id].q.score - P[a.id].q.score; });
            var dec = sansId ? 1 : 0;
            l.forEach(function (c, i) { c.el.style.setProperty('--k', i + dec); });
        }
        function fabriquer(id) {
            var p = P[id], q = p.q, el = doc.createElement('article');
            el.className = 'carte n-' + palier(q.score);
            el.setAttribute('data-id', id); el.tabIndex = 0;
            var crit = criteres(p).map(function (c) { return '<li' + (c[1] ? '' : ' class="non"') + '>' + esc(c[0]) + '</li>'; }).join('');
            el.innerHTML = '<div class="c-corps"><div class="c-l1"><span class="c-src">' + esc(p.src) + '</span><b class="c-nom">' + esc(p.nom) + '</b><span class="c-alerte">À appeler maintenant</span>' +
                (p.proprio ? '<span class="c-proprio"><svg aria-hidden="true"><use href="#i-maison"/></svg>Déjà propriétaire</span>' : '') +
                '</div><p class="c-det">' + esc(p.det) + '</p><ul class="c-crit">' + crit + '</ul></div><div class="c-sc"><span class="c-num">' + q.score + '</span><small>' + niveau(q.score) + '</small></div>';
            var r = function (a) { return (Math.random() * 2 - 1) * a; };
            el.style.setProperty('--mx', r(36).toFixed(0) + 'px');
            el.style.setProperty('--my', (120 + Math.random() * 110).toFixed(0) + 'px');
            el.style.setProperty('--mr', r(8).toFixed(1) + 'deg');
            el.style.setProperty('--d', '0s');
            brancher(el);
            return el;
        }

        /* calcul détaillé au survol */
        var montree = null;
        function montrer(el) {
            var p = P[el.getAttribute('data-id')]; if (!p || scene.getAttribute('data-etat') !== 'avec' || el.classList.contains('brut')) return;
            montree = el;
            $$('.carte.montre', scene).forEach(function (c) { c.classList.remove('montre'); });
            el.classList.add('montre');
            var html = '<b><span>' + esc(p.nom) + '</span><span>' + p.q.score + '/100</span></b><ul>' +
                p.q.lignes.map(function (x) { return '<li' + (x.plafond ? ' class="plafond"' : '') + '><i>' + (x.n > 0 ? '+' : '') + x.n + '</i>' + esc(x.t) + '</li>'; }).join('') +
                '</ul><p>Règles de calcul de Zelyro pour un projet d’achat.' + (p.proprio ? ' Déjà propriétaire&nbsp;: à proposer pour une estimation.' : '') + '</p>';
            calc.innerHTML = html;
            calc.hidden = false;
            var rt = tableau.getBoundingClientRect(), rc = el.getBoundingClientRect();
            var h = calc.offsetHeight, haut = rc.bottom - rt.top + 8;
            if (haut + h > rt.height + 40) haut = rc.top - rt.top - h - 8;
            calc.style.top = Math.max(8, haut) + 'px';
            requestAnimationFrame(function () { calc.classList.add('ouvert'); });
        }
        function cacher(el) {
            if (el && montree !== el) return;
            montree = null;
            calc.classList.remove('ouvert');
            $$('.carte.montre', scene).forEach(function (c) { c.classList.remove('montre'); });
        }
        function brancher(el) {
            el.addEventListener('mouseenter', function () { montrer(el); });
            el.addEventListener('mouseleave', function () { cacher(el); });
            el.addEventListener('focus', function () { montrer(el); });
            el.addEventListener('blur', function () { cacher(el); });
            el.addEventListener('click', function () { if (montree === el) cacher(el); else montrer(el); });
        }
        cartes.forEach(function (c) { brancher(c.el); });

        /* sans / avec */
        var bs = $('.b-sans'), ba = $('.b-avec'), touche = false;
        function etat(e) {
            scene.setAttribute('data-etat', e);
            bs.setAttribute('aria-pressed', e === 'sans'); ba.setAttribute('aria-pressed', e === 'avec');
            cacher();
        }
        bs.addEventListener('click', function () { touche = true; etat('sans'); });
        ba.addEventListener('click', function () { touche = true; etat('avec'); });
        if (!reduit) {
            etat('sans');
            setTimeout(function () { if (!touche) etat('avec'); }, 1500);
        }

        /* arrivées en direct */
        var direct = $('#direct'), actif = !reduit, visible = true, survol = false, minuterie = null;
        if (reduit) return;
        direct.hidden = false;
        direct.addEventListener('click', function () {
            actif = !actif;
            direct.setAttribute('aria-pressed', actif ? 'true' : 'false');
            $('.direct-txt', direct).textContent = actif ? 'En direct' : 'En pause';
            $('use', direct).setAttribute('href', actif ? '#i-pause' : '#i-lecture');
            direct.setAttribute('aria-label', actif ? 'Mettre en pause l’arrivée des demandes' : 'Reprendre l’arrivée des demandes');
        });
        direct.setAttribute('aria-label', 'Mettre en pause l’arrivée des demandes');
        tableau.addEventListener('mouseenter', function () { survol = true; });
        tableau.addEventListener('mouseleave', function () { survol = false; });
        if ('IntersectionObserver' in window) {
            new IntersectionObserver(function (en) { visible = en[0].isIntersecting; }, { threshold: 0.3 }).observe(tableau);
        }
        function prochain() {
            var vus = cartes.filter(function (c) { return !c.sort; }).map(function (c) { return c.id; });
            for (var n = 0; n < file.length; n++) {
                var id = file[(iFile + n) % file.length];
                if (vus.indexOf(id) < 0) { iFile = (iFile + n + 1) % file.length; return id; }
            }
            return null;
        }
        function arrivee() {
            if (!actif || !visible || survol || doc.hidden || scene.getAttribute('data-etat') !== 'avec' || $('.carte.brut', scene)) return;
            var id = prochain(); if (!id) return;
            cacher();
            // la demande la plus ancienne quitte l'aperçu
            var vivantes = cartes.filter(function (c) { return !c.sort; });
            var vieille = vivantes.reduce(function (a, b) { return a.age < b.age ? a : b; });
            vieille.sort = true; vieille.el.classList.add('sort');
            setTimeout(function () { vieille.el.remove(); cartes = cartes.filter(function (c) { return c !== vieille; }); }, 700);
            var el = fabriquer(id), q = P[id].q;
            el.classList.add('brut', 'entre');
            el.classList.remove('n-' + palier(q.score));
            var num = $('.c-num', el), lab = $('.c-sc small', el);
            num.textContent = '··'; lab.textContent = 'Lecture…';
            var badge = doc.createElement('span'); badge.className = 'c-nouveau'; badge.textContent = 'Nouvelle demande';
            el.appendChild(badge);
            el.style.setProperty('--k', 0);
            scene.appendChild(el);
            var c = { id: id, el: el, age: ++age };
            cartes.push(c);
            ranger(id);
            void el.offsetWidth;
            el.classList.remove('entre');
            setTimeout(function () {
                el.classList.remove('brut');
                el.classList.add('n-' + palier(q.score));
                lab.textContent = niveau(q.score);
                compteur(num, 0, q.score, 800);
            }, 1300);
            setTimeout(function () {
                badge.remove();
                ranger();
            }, 2500);
        }
        minuterie = setInterval(arrivee, 5200);
    })();

    /* ---------- Constat : cartes à retourner ---------- */
    $$('.r-in').forEach(function (b) {
        b.addEventListener('click', function () { b.setAttribute('aria-pressed', b.getAttribute('aria-pressed') === 'true' ? 'false' : 'true'); });
    });

    /* ---------- Vidéo ---------- */
    (function () {
        var v = $('#demo-video'), b = $('#lire');
        if (!v || !b) return;
        b.hidden = false;
        b.addEventListener('click', function () { var p = v.play(); if (p && p.catch) p.catch(function () {}); });
        v.addEventListener('play', function () { b.hidden = true; });
        v.addEventListener('ended', function () { b.hidden = false; });
    })();

    /* ---------- Chapitres des fonctionnalités ---------- */
    (function () {
        var liens = $$('#chapitres a');
        if (!liens.length || !('IntersectionObserver' in window)) return;
        var io = new IntersectionObserver(function (en) {
            en.forEach(function (e) {
                if (!e.isIntersecting) return;
                liens.forEach(function (l) {
                    var on = l.getAttribute('data-c') === e.target.id;
                    l.classList.toggle('actif', on);
                    if (on) { l.setAttribute('aria-current', 'true'); var n = l.parentNode; n.scrollTo({ left: l.offsetLeft - n.clientWidth / 2 + l.clientWidth / 2, behavior: reduit ? 'auto' : 'smooth' }); }
                    else l.removeAttribute('aria-current');
                });
            });
        }, { rootMargin: '-40% 0px -55% 0px' });
        liens.forEach(function (l) { var s = doc.getElementById(l.getAttribute('data-c')); if (s) io.observe(s); });
    })();

    /* ---------- 01 Qualifier : composez un prospect ---------- */
    (function () {
        var f = $('#q-form'); if (!f) return;
        var res = $('#q-resultat'), num = $('#q-num'), statut = $('#q-statut'), barre = $('#q-barre'), lignes = $('#q-lignes'), defi = $('#q-defi'), pro = $('#q-proprio');
        var precedent = 66, deja90 = false;
        var PROFILS = {
            camille: { fin: 'approved', urg: 'immediate', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['formulaire_rempli'], proprio: 0 },
            julien: { fin: 'in_progress', urg: '3-6', email: 1, tel: 1, budget: 1, secteur: 1, type: 1, eng: ['interet_bien', 'formulaire_rempli'], proprio: 1 },
            sophie: { fin: '', urg: '6plus', email: 1, tel: 0, budget: 0, secteur: 0, type: 1, eng: ['formulaire_ouvert'], proprio: 0 },
            vide: { fin: '', urg: '', email: 0, tel: 0, budget: 0, secteur: 0, type: 0, eng: [], proprio: 0 }
        };
        function lire() {
            var v = function (n) { var x = f.querySelector('input[name="' + n + '"]:checked'); return x ? x.value : ''; };
            var c = function (n) { return f.querySelector('input[name="' + n + '"]').checked ? 1 : 0; };
            return { fin: v('fin'), urg: v('urg'), email: c('email'), tel: c('tel'), budget: c('budget'), secteur: c('secteur'), type: c('type'),
                eng: $$('input[name="eng"]:checked', f).map(function (x) { return x.value; }), proprio: c('proprio') };
        }
        function ecrire(p) {
            $$('input[name="fin"]', f).forEach(function (x) { x.checked = x.value === p.fin; });
            $$('input[name="urg"]', f).forEach(function (x) { x.checked = x.value === p.urg; });
            ['email', 'tel', 'budget', 'secteur', 'type', 'proprio'].forEach(function (n) { f.querySelector('input[name="' + n + '"]').checked = !!p[n]; });
            $$('input[name="eng"]', f).forEach(function (x) { x.checked = p.eng.indexOf(x.value) >= 0; });
        }
        function rendre(anim) {
            var p = lire(), q = qualifier(p), s = q.score, n = palier(s);
            res.setAttribute('data-niveau', n);
            var mini = $('#q-mini'); if (mini) { mini.setAttribute('data-niveau', n); $('#q-mini-num').textContent = s; $('#q-mini-txt').textContent = s >= 90 ? 'À appeler maintenant' : niveau(s); }
            statut.textContent = niveau(s);
            pro.classList.toggle('cache', !p.proprio);
            pro.setAttribute('aria-hidden', p.proprio ? 'false' : 'true');
            compteur(num, precedent, s, anim === false ? 1 : 600);
            precedent = s;
            var segs = ['fin', 'urg', 'coord', 'dos', 'eng'].map(function (k) { return '<i class="' + COUL[k] + '" style="flex-grow:' + Math.max(0, q.cat[k]) + '"></i>'; }).join('') + '<i style="flex-grow:' + (100 - s) + '"></i>';
            barre.innerHTML = segs;
            lignes.innerHTML = q.lignes.length ? q.lignes.map(function (x) {
                return '<li><span class="' + COUL[x.c] + '"></span><i>' + (x.n > 0 ? '+' : '') + x.n + '</i>' + esc(x.t) + '</li>';
            }).join('') : '<li class="vide">Aucune information&nbsp;: ce prospect reste en premier contact.</li>';
            if (s >= 90) {
                defi.textContent = 'Vert fluo : ce prospect passe en tête de votre liste.';
                defi.classList.add('gagne');
                if (!deja90 && anim !== false) {
                    var r = res.getBoundingClientRect();
                    eclats(r.left + r.width / 2, r.top + 120, ['#39FF14', '#D4B15F', '#1F3A2E', '#FFFDF9']);
                }
                deja90 = true;
            } else {
                var manque = 90 - s;
                defi.textContent = 'Encore ' + manque + ' point' + (manque > 1 ? 's' : '') + ' pour passer au vert fluo.';
                defi.classList.remove('gagne');
                if (s < 80) deja90 = false;
            }
        }
        f.addEventListener('change', function () { rendre(); });
        f.addEventListener('submit', function (e) { e.preventDefault(); });
        $$('[data-profil]').forEach(function (b) {
            b.addEventListener('click', function () { ecrire(PROFILS[b.getAttribute('data-profil')]); rendre(); });
        });
        rendre(false);
    })();

    /* ---------- 02 Rapprocher : quel bien pour Julien ? ---------- */
    (function () {
        var zone = $('#r-biens'); if (!zone) return;
        var LEAD = { budget: 560000, type: 'Maison', secteur: 'Marcq-en-Barœul', fin: 'in_progress', urg: '3-6' };
        var BIENS = [
            { type: 'Maison', ville: 'Marcq-en-Barœul', prix: 545000 },
            { type: 'Maison', ville: 'Marcq-en-Barœul', prix: 640000 },
            { type: 'Appartement', ville: 'Marcq-en-Barœul', prix: 520000 },
            { type: 'Maison', ville: 'Roubaix', prix: 530000 }
        ];
        var choisi = 0, prix = BIENS[0].prix;
        var curseur = $('#r-prix'), sortie = $('#r-prix-val'), val = $('#ra-val'), sc = $('#r-score'), sr = $('#r-score-sr'), raisons = $('#r-raisons'), boite = $('.r-resultat');
        var ancien = 93;
        function pointsBudget(b, p) {
            var e = Math.abs(p - b) / b, pct = Math.round(e * 100);
            if (e < 0.05) return [20, pct === 0 ? 'Budget quasi identique au prix' : 'Budget très proche du prix (écart de ' + pct + ' %)'];
            if (e < 0.10) return [18, 'Budget très proche du prix (écart de ' + pct + ' %)'];
            if (e < 0.15) return [15, 'Budget proche du prix (écart de ' + pct + ' %)'];
            if (e < 0.20) return [12, 'Budget proche du prix (écart de ' + pct + ' %)'];
            if (e < 0.30) return [8, 'Prix à ' + pct + ' % du budget, à discuter'];
            return [0, null];
        }
        function calcul(b, p) {
            if (b.ville !== LEAD.secteur) return { s: 0, l: [], exclu: 'Hors du secteur recherché' };
            var l = [], s = 0, pb = pointsBudget(LEAD.budget, p);
            if (pb[1]) l.push([pb[0], pb[1]]); s += pb[0];
            if (b.type === LEAD.type) { s += 30; l.push([30, 'Même type de bien : ' + b.type]); }
            else { s += 15; l.push([15, 'Type voisin (appartement ou maison)']); }
            s += 20; l.push([20, 'Secteur recherché : ' + LEAD.secteur]);
            s += 15; l.push([15, 'Financement en cours']);
            s += 8; l.push([8, 'Achat prévu sous 3 à 6 mois']);
            return { s: Math.min(100, s), l: l };
        }
        function plein() {
            var p = (curseur.value - curseur.min) / (curseur.max - curseur.min) * 100;
            curseur.style.setProperty('--p', p + '%');
        }
        function rendre() {
            var r = calcul(BIENS[choisi], prix);
            sortie.textContent = euros(prix);
            plein();
            val.style.strokeDashoffset = (326.7 * (1 - r.s / 100)).toFixed(1);
            boite.classList.toggle('zero', r.s === 0);
            compteur(sc, ancien, r.s, 500); ancien = r.s;
            sr.textContent = r.s + ' sur 100';
            raisons.innerHTML = r.exclu ? '<li class="exclu">' + r.exclu + '&nbsp;: le secteur est éliminatoire.</li>' :
                r.l.map(function (x) { return '<li><i>+' + x[0] + '</i>' + esc(x[1]) + '</li>'; }).join('');
        }
        var boutons = $$('.r-bien', zone);
        function choisir(i, focus) {
            choisi = i; prix = BIENS[i].prix; curseur.value = prix;
            boutons.forEach(function (b, j) { b.setAttribute('aria-checked', j === i ? 'true' : 'false'); b.tabIndex = j === i ? 0 : -1; });
            if (focus) boutons[i].focus();
            rendre();
        }
        boutons.forEach(function (b, i) {
            b.tabIndex = i === 0 ? 0 : -1;
            b.addEventListener('click', function () { choisir(i); });
            b.addEventListener('keydown', function (e) {
                var d = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
                if (d) { e.preventDefault(); choisir((i + d + boutons.length) % boutons.length, true); }
            });
        });
        curseur.addEventListener('input', function () { prix = +curseur.value; rendre(); });
        rendre();
    })();

    /* ---------- 03 Estimer : les ventes comparables ---------- */
    (function () {
        var g = $('#e-points'), carte = $('#e-carte'), info = $('#e-info');
        if (!g) return;
        var graine = 7;
        function alea() { graine = (graine * 16807) % 2147483647; return (graine - 1) / 2147483646; }
        var ns = 'http://www.w3.org/2000/svg', pts = [];
        for (var i = 0; i < 39; i++) {
            var a = alea() * Math.PI * 2, d = 34 + Math.sqrt(alea()) * 128;
            var x = 256 + Math.cos(a) * d, y = 214 + Math.sin(a) * d;
            var surf = Math.round(38 + alea() * 58), m2 = Math.round((4600 + (alea() + alea() - 1) * 650) / 10) * 10;
            var an = 2023 + Math.floor(alea() * 3), maison = alea() < 0.18;
            var c = doc.createElementNS(ns, 'circle');
            c.setAttribute('cx', x.toFixed(1)); c.setAttribute('cy', y.toFixed(1)); c.setAttribute('r', 6);
            c.setAttribute('class', 'e-pt');
            c.setAttribute('fill', m2 < 4350 ? '#A9B9A2' : m2 < 4850 ? '#4F6353' : '#1F3A2E');
            c.setAttribute('stroke', '#FFFDF9'); c.setAttribute('stroke-width', '2');
            c.style.transitionDelay = (0.3 + i * 0.035).toFixed(2) + 's';
            c._d = { t: (maison ? 'Maison' : 'Appartement') + ' · ' + surf + ' m²', m2: m2, an: an, prix: Math.round(surf * m2 / 1000) * 1000 };
            g.appendChild(c); pts.push(c);
        }
        function montre(c) {
            pts.forEach(function (p) { p.classList.toggle('actif', p === c); });
            var r = carte.getBoundingClientRect(), rc = c.getBoundingClientRect();
            info.innerHTML = '<b>' + nf(c._d.m2) + ' €/m²</b><br>' + esc(c._d.t) + ' · vendu ' + euros(c._d.prix) + ' en ' + c._d.an;
            info.style.left = (rc.left - r.left + rc.width / 2) + 'px';
            info.style.top = (rc.top - r.top) + 'px';
            info.hidden = false;
        }
        pts.forEach(function (c) {
            c.addEventListener('mouseenter', function () { montre(c); });
            c.addEventListener('click', function () { montre(c); });
        });
        carte.addEventListener('mouseleave', function () { info.hidden = true; pts.forEach(function (p) { p.classList.remove('actif'); }); });
        quandVisible(carte, function () {
            setTimeout(function () { pts.forEach(function (c) { c.style.transitionDelay = '0s'; }); }, 2200);
            compteur($('#e-nb'), 0, 39, 1500);
        });
    })();

    /* ---------- 04 Suivre : faites avancer Julien ---------- */
    (function () {
        var piste = $('#s-piste'); if (!piste) return;
        var rail = $('#s-rail').parentNode, etapes = $$('#s-etapes li'), journal = $('#s-journal'), suivant = $('#s-suivant'), perdu = $('#s-perdu'), zero = $('#s-zero');
        var NOTES = [
            null,
            [['Note', 'Premier appel : cherche une maison avec jardin, prêt en cours.'], ['Relance', 'Rappeler jeudi pour proposer deux visites.', 1]],
            [['Note', 'Souhaite une seconde visite avec son conjoint.']],
            [['Note', 'Offre au prix, à transmettre au vendeur.']],
            [['Note', 'Compromis signé. Penser à l’estimation de son bien actuel.']]
        ];
        var points = [];
        for (var i = 0; i < 5; i++) { var d = doc.createElement('span'); d.className = 's-rail-dot'; d.style.left = (i * 25) + '%'; rail.insertBefore(d, rail.firstChild); points.push(d); }
        var s = 0, fini = false;
        function ajout(t, x, rappel) {
            var li = doc.createElement('li'); if (rappel) li.className = 'rappel';
            li.innerHTML = '<time>' + esc(t) + '</time><span>' + esc(x) + '</span>';
            journal.insertBefore(li, journal.firstChild);
            while (journal.children.length > 4) journal.removeChild(journal.lastChild);
        }
        function maj() {
            piste.style.setProperty('--s', s / 4);
            etapes.forEach(function (e, i) { e.classList.toggle('fait', i <= s); e.classList.toggle('ici', i === s); if (i === s) e.setAttribute('aria-current', 'step'); else e.removeAttribute('aria-current'); });
            points.forEach(function (p, i) { p.classList.toggle('fait', i <= s); });
            suivant.disabled = fini; perdu.disabled = fini;
        }
        suivant.addEventListener('click', function () {
            if (fini || s >= 4) return;
            s++;
            (NOTES[s] || []).forEach(function (n) { ajout(n[0], n[1], n[2]); });
            if (s === 4) {
                fini = true; piste.classList.add('signe');
                var r = $('.s-jeton', piste).getBoundingClientRect();
                setTimeout(function () { eclats(r.left + r.width / 2, r.top, ['#D4B15F', '#EBD9A6', '#1F3A2E', '#A9B9A2']); }, 500);
            }
            maj();
            if (fini) zero.focus();
        });
        perdu.addEventListener('click', function () {
            if (fini) return;
            fini = true; piste.classList.add('perdu');
            ajout('Perdu', 'A trouvé un bien par une autre agence. Le motif est gardé dans l’historique.');
            maj(); zero.focus();
        });
        zero.addEventListener('click', function () {
            s = 0; fini = false; piste.classList.remove('signe', 'perdu');
            journal.innerHTML = '';
            ajout('Note', 'Demande reçue depuis le site de l’agence : maison à Marcq-en-Barœul.');
            maj();
        });
        maj();
    })();

    /* ---------- Comment ça marche : du mail au prospect ---------- */
    (function () {
        var m = $('#p-machine'); if (!m) return;
        var marks = $$('mark', m), lignes = $$('.p-fiche dl div', m), etapes = $$('#p-etapes li'), sc = $('#p-sc'), rejouer = $('#p-rejouer');
        var ORDRE = ['nom', 'tel', 'mail', 'bien', 'budget', 'fin', 'urg'];
        var timers = [];
        function t(fn, d) { timers.push(setTimeout(fn, d)); }
        function etape(n) { m.setAttribute('data-etape', n); etapes.forEach(function (li) { li.classList.toggle('actif', +li.getAttribute('data-e') === n); }); }
        function depart() {
            timers.forEach(clearTimeout); timers = [];
            marks.forEach(function (x) { x.classList.remove('on'); });
            lignes.forEach(function (x) { x.classList.remove('on'); });
            sc.className = 'p-sc'; sc.textContent = '··';
            etape(1);
        }
        function jouer() {
            depart();
            rejouer.hidden = true;
            t(function () { etape(2); }, 1200);
            ORDRE.forEach(function (c, i) {
                t(function () {
                    marks.forEach(function (x) { if (x.getAttribute('data-c') === c) x.classList.add('on'); });
                }, 1400 + i * 420);
                t(function () {
                    lignes.forEach(function (x) { if (x.getAttribute('data-c') === c) x.classList.add('on'); });
                }, 1650 + i * 420);
            });
            var fin = 1650 + ORDRE.length * 420 + 300;
            t(function () {
                etape(3);
                sc.className = 'p-sc n-orange';
                sc.innerHTML = '<span>0</span> <small>Projet en cours</small>';
                compteur($('span', sc), 0, 56, 800);
            }, fin);
            t(function () { rejouer.hidden = false; }, fin + 900);
        }
        function final() {
            marks.forEach(function (x) { x.classList.add('on'); });
            lignes.forEach(function (x) { x.classList.add('on'); });
            sc.className = 'p-sc n-orange'; sc.innerHTML = '56 <small>Projet en cours</small>';
            etape(3);
        }
        if (reduit) { final(); return; }
        depart();
        quandVisible(m, jouer, { threshold: 0.45 });
        rejouer.addEventListener('click', jouer);
    })();

    /* ---------- Simulateur ---------- */
    (function () {
        var ids = ['s-leads', 's-perdues', 's-rattrapees', 's-transfo', 's-commission', 's-forfait'];
        var el = {}; ids.forEach(function (i) { el[i] = doc.getElementById(i); });
        if (!el['s-leads']) return;
        var barres = $('#sr-barres'), cout = $('#sr-cout'), ns = 'http://www.w3.org/2000/svg';
        var bs = [];
        for (var m = 0; m < 12; m++) {
            var r = doc.createElementNS(ns, 'rect'); r.setAttribute('class', 'sr-barre'); r.setAttribute('rx', 4);
            r.setAttribute('x', 8 + m * 32.5); r.setAttribute('width', 22); r.setAttribute('y', 130); r.setAttribute('height', 0);
            barres.appendChild(r); bs.push(r);
            var tx = doc.createElementNS(ns, 'text'); tx.setAttribute('class', 'sr-mois'); tx.setAttribute('x', 19 + m * 32.5); tx.setAttribute('y', 146); tx.setAttribute('text-anchor', 'middle'); tx.textContent = m + 1;
            barres.appendChild(tx);
        }
        function lire(id, max) { var v = parseFloat(String(el[id].value).replace(',', '.')); if (!isFinite(v) || v < 0) v = 0; return Math.min(v, max); }
        function plein(i) { var x = el[i]; if (x.type !== 'range') return; x.style.setProperty('--p', ((x.value - x.min) / (x.max - x.min) * 100) + '%'); }
        var ancien = 6480;
        function calcul() {
            var leads = lire('s-leads', 100000), perdues = lire('s-perdues', 100) / 100, rattr = lire('s-rattrapees', 100) / 100;
            var transfo = lire('s-transfo', 100) / 100, commission = lire('s-commission', 1000000), mensuel = parseFloat(el['s-forfait'].value) || 0;
            var sansSuite = leads * perdues, rattrapees = sansSuite * rattr;
            var ventes = rattrapees * transfo * 12, gain = ventes * commission, coutAn = mensuel * 12;
            $('#o-leads').textContent = nf(leads);
            $('#o-perdues').textContent = nf(perdues * 100) + ' %';
            $('#o-rattrapees').textContent = nf(rattr * 100) + ' %';
            $('#o-transfo').textContent = nf(transfo * 100, 1) + ' %';
            $('#o-commission').textContent = nf(commission) + ' € HT';
            ids.forEach(plein);
            $('#r-perdues').textContent = nf(sansSuite, 1);
            $('#r-rattrapees').textContent = nf(rattrapees, 1);
            $('#r-ventes').textContent = nf(ventes, 1);
            compteur($('#r-commission'), ancien, Math.round(gain), 450, euros); ancien = Math.round(gain);
            var seuil = $('#r-seuil');
            if (commission > 0) {
                var n = coutAn / commission, arr = Math.round(n * 10) / 10;
                var exact = arr < 0.1 ? 'moins de 0,1' : nf(arr, 1);
                seuil.textContent = 'Le forfait coûte ' + nf(coutAn) + ' € HT par an, soit ' + exact + ' vente' + (n >= 2 ? 's' : '') +
                    ' de ' + nf(commission) + ' € : ' +
                    (n <= 1 ? 'une seule vente supplémentaire par an le couvre.' : 'il est couvert dès ' + nf(Math.ceil(n)) + ' ventes supplémentaires par an.');
            } else {
                seuil.textContent = 'Indiquez votre commission moyenne pour voir le seuil.';
            }
            var max = Math.max(gain, coutAn, 1) * 1.08, H = 120, d = '';
            bs.forEach(function (r, i) {
                var cum = gain / 12 * (i + 1), h = cum / max * H;
                r.setAttribute('y', (130 - h).toFixed(1)); r.setAttribute('height', h.toFixed(1));
                r.setAttribute('class', 'sr-barre' + (cum < mensuel * (i + 1) ? ' sous' : ''));
                var y = 130 - mensuel * (i + 1) / max * H, x = 19 + i * 32.5;
                d += (i ? ' L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1);
            });
            cout.setAttribute('d', d);
        }
        ids.forEach(function (i) { el[i].addEventListener('input', calcul); el[i].addEventListener('change', calcul); });
        $('#simu-form').addEventListener('submit', function (e) { e.preventDefault(); });
        calcul();
    })();

    /* ---------- Sécurité : le trajet des données ---------- */
    (function () {
        var noeuds = $$('.noeud'), details = $$('#circuit-detail div'), circuit = $('#circuit');
        if (!noeuds.length) return;
        var auto = !reduit, i = 0, minut = null, visible = false;
        function choisir(n) {
            i = n;
            noeuds.forEach(function (b, j) { b.setAttribute('aria-pressed', j === n ? 'true' : 'false'); });
            details.forEach(function (d) { d.classList.toggle('actif', +d.getAttribute('data-n') === n); });
        }
        noeuds.forEach(function (b, j) { b.addEventListener('click', function () { auto = false; choisir(j); }); });
        choisir(0);
        var svg = $('.circuit-fils', circuit);
        if (reduit && svg && svg.pauseAnimations) svg.pauseAnimations();
        if (!auto) return;
        if ('IntersectionObserver' in window) new IntersectionObserver(function (en) { visible = en[0].isIntersecting; }, { threshold: 0.4 }).observe(circuit);
        minut = setInterval(function () { if (!auto) { clearInterval(minut); return; } if (visible && !doc.hidden) choisir((i + 1) % noeuds.length); }, 3800);
    })();

    /* ---------- Tarifs : quel forfait pour votre volume ? ---------- */
    (function () {
        var c = $('#t-volume'); if (!c) return;
        var out = $('#t-volume-val'), reco = $('#t-reco'), cartes = $$('.forfait');
        var F = [[300, 'Essentiel', '300'], [1500, 'Agence', '1 500'], [6000, 'Réseau', '6 000']];
        function maj() {
            var v = +c.value, k = v <= 300 ? 0 : v <= 1500 ? 1 : 2;
            out.textContent = nf(v);
            c.style.setProperty('--p', ((v - c.min) / (c.max - c.min) * 100) + '%');
            reco.innerHTML = 'Le forfait <b>' + F[k][1] + '</b> couvre jusqu’à ' + F[k][2] + ' prospects par mois.';
            cartes.forEach(function (x) { x.classList.toggle('conseille', +x.getAttribute('data-f') === k + 1); });
        }
        c.addEventListener('input', maj);
        maj();
    })();
})();
