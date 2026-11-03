/* Lecteur de fichiers Excel (.xlsx / .xlsm) pour Zelyro.
 *
 * Écrit pour Zelyro, sans dépendance : un fichier .xlsx est une archive ZIP
 * qui contient du XML. Tout se passe dans le navigateur, le fichier n'est
 * jamais envoyé à un tiers (la politique de sécurité du site n'autorise
 * d'ailleurs que les scripts du site lui-même).
 *
 *   const lignes = await lireExcel(arrayBuffer);   // tableau de lignes, chaque ligne = tableau de textes
 *
 * Retourne la première feuille visible qui contient des données, comme le
 * ferait un export CSV. Les lignes entièrement vides sont ignorées.
 * Lève une Error au message lisible (en français) si le fichier n'est pas lisible.
 */
(function () {
    'use strict';

    var MAX_OCTETS_XML = 40 * 1024 * 1024;   // taille maximale d'une partie une fois décompressée
    var MAX_COLONNES = 200;
    var MAX_LIGNES = 20000;

    function octets(buffer) { return buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer); }

    // Un vrai .xlsx commence par « PK » (ZIP) ; l'ancien format .xls, et les classeurs
    // protégés par mot de passe, commencent par la signature OLE D0 CF 11 E0.
    function typeDeFichier(buffer) {
        var b = octets(buffer);
        if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4B) return 'xlsx';
        if (b.length >= 4 && b[0] === 0xD0 && b[1] === 0xCF && b[2] === 0x11 && b[3] === 0xE0) return 'xls';
        return 'autre';
    }

    // ---------------------------------------------------------------- ZIP
    function lireZip(buffer) {
        var b = octets(buffer);
        var vue = new DataView(b.buffer, b.byteOffset, b.byteLength);
        var fin = -1;
        for (var i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
            if (vue.getUint32(i, true) === 0x06054B50) { fin = i; break; }
        }
        if (fin < 0) throw new Error('Ce fichier Excel est abîmé ou n\'est pas un classeur .xlsx.');
        var nombre = vue.getUint16(fin + 10, true);
        var pos = vue.getUint32(fin + 16, true);
        var entrees = {};
        for (var n = 0; n < nombre; n++) {
            if (pos + 46 > b.length || vue.getUint32(pos, true) !== 0x02014B50) break;
            var methode = vue.getUint16(pos + 10, true);
            var tailleComp = vue.getUint32(pos + 20, true);
            var tailleOrig = vue.getUint32(pos + 24, true);
            var lNom = vue.getUint16(pos + 28, true);
            var lExtra = vue.getUint16(pos + 30, true);
            var lCom = vue.getUint16(pos + 32, true);
            var local = vue.getUint32(pos + 42, true);
            var nom = new TextDecoder('utf-8').decode(b.subarray(pos + 46, pos + 46 + lNom));
            entrees[nom] = { methode: methode, tailleComp: tailleComp, tailleOrig: tailleOrig, local: local };
            pos += 46 + lNom + lExtra + lCom;
        }
        return { b: b, vue: vue, entrees: entrees };
    }

    async function extraire(zip, nom) {
        var e = zip.entrees[nom];
        if (!e) return null;
        if (e.tailleOrig > MAX_OCTETS_XML) throw new Error('Ce fichier Excel est trop volumineux une fois décompressé.');
        var p = e.local;
        if (p + 30 > zip.b.length || zip.vue.getUint32(p, true) !== 0x04034B50) throw new Error('Ce fichier Excel est abîmé.');
        var debut = p + 30 + zip.vue.getUint16(p + 26, true) + zip.vue.getUint16(p + 28, true);
        var donnees = zip.b.subarray(debut, debut + e.tailleComp);
        if (e.methode === 0) return new TextDecoder('utf-8').decode(donnees);
        if (e.methode !== 8) throw new Error('Ce fichier Excel utilise une compression non prise en charge.');
        if (typeof DecompressionStream === 'undefined') {
            throw new Error('Ce navigateur ne sait pas ouvrir les fichiers Excel. Mettez-le à jour, ou enregistrez le fichier au format CSV.');
        }
        var flux = new Blob([donnees]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
        var lecteur = flux.getReader();
        var morceaux = [], total = 0;
        for (;;) {
            var r = await lecteur.read();
            if (r.done) break;
            total += r.value.length;
            if (total > MAX_OCTETS_XML) { lecteur.cancel(); throw new Error('Ce fichier Excel est trop volumineux une fois décompressé.'); }
            morceaux.push(r.value);
        }
        var tout = new Uint8Array(total), o = 0;
        morceaux.forEach(function (m) { tout.set(m, o); o += m.length; });
        return new TextDecoder('utf-8').decode(tout);
    }

    // ---------------------------------------------------------------- XML
    function xml(texte) {
        var doc = new DOMParser().parseFromString(texte, 'application/xml');
        if (doc.getElementsByTagName('parsererror').length) throw new Error('Ce fichier Excel est abîmé.');
        return doc;
    }
    function tous(noeud, local) { return Array.prototype.slice.call(noeud.getElementsByTagNameNS('*', local)); }
    function enfants(noeud, local) {
        return Array.prototype.filter.call(noeud.childNodes, function (n) { return n.nodeType === 1 && n.localName === local; });
    }
    function attr(noeud, nom) { return noeud.getAttribute(nom); }

    function chaines(texte) {
        if (!texte) return [];
        // <si> contient soit <t>, soit des morceaux <r><t> ; <rPh> (phonétique japonaise) est ignoré.
        return tous(xml(texte), 'si').map(function (si) {
            var s = '';
            Array.prototype.forEach.call(si.childNodes, function (n) {
                if (n.nodeType !== 1) return;
                if (n.localName === 't') s += n.textContent;
                else if (n.localName === 'r') enfants(n, 't').forEach(function (t) { s += t.textContent; });
            });
            return s;
        });
    }

    // Formats de date : numéros intégrés d'Excel + formats personnalisés qui contiennent d (jour) ou y (année).
    var DATES_INTEGREES = { 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 1, 21: 1, 22: 1, 45: 1, 46: 1, 47: 1 };
    function stylesDates(texte) {
        var estDate = [];
        if (!texte) return estDate;
        var doc = xml(texte);
        var perso = {};
        tous(doc, 'numFmt').forEach(function (f) {
            var code = (attr(f, 'formatCode') || '').replace(/"[^"]*"|\[[^\]]*\]|\\.|_.|\*./g, '');
            perso[attr(f, 'numFmtId')] = /[dy]/i.test(code) && !/[#0]/.test(code);
        });
        var cellXfs = tous(doc, 'cellXfs')[0];
        if (cellXfs) {
            enfants(cellXfs, 'xf').forEach(function (xf, i) {
                var id = attr(xf, 'numFmtId');
                estDate[i] = !!DATES_INTEGREES[id] || perso[id] === true;
            });
        }
        return estDate;
    }
    function dateExcel(serie) {
        var n = parseFloat(serie);
        if (!isFinite(n)) return serie;
        var d = new Date(Math.round((n - 25569) * 86400000));   // 25569 = 1er janvier 1970 en jours Excel
        var p = function (x) { return (x < 10 ? '0' : '') + x; };
        var texte = p(d.getUTCDate()) + '/' + p(d.getUTCMonth() + 1) + '/' + d.getUTCFullYear();
        return n % 1 !== 0 ? texte + ' ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) : texte;
    }
    function nombre(v) {
        var n = Number(v);
        if (!isFinite(n)) return v;
        return Math.abs(n) < 1e15 ? String(parseFloat(n.toPrecision(15))) : v;   // 395000, pas 3.95E5 ni 394999.99999999994
    }

    function colonne(ref) {
        var m = /^([A-Z]+)/i.exec(ref || ''), n = 0;
        if (!m) return -1;
        for (var i = 0; i < m[1].length; i++) n = n * 26 + (m[1].toUpperCase().charCodeAt(i) - 64);
        return n - 1;
    }

    function lignesFeuille(texte, partages, estDate) {
        var doc = xml(texte);
        var sortie = [];
        var rangees = tous(doc, 'row');
        for (var r = 0; r < rangees.length && sortie.length < MAX_LIGNES; r++) {
            var ligne = [], suivante = 0, vide = true;
            var cellules = enfants(rangees[r], 'c');
            for (var k = 0; k < cellules.length; k++) {
                var c = cellules[k];
                var col = colonne(attr(c, 'r'));
                if (col < 0) col = suivante;
                if (col >= MAX_COLONNES) continue;
                suivante = col + 1;
                var type = attr(c, 't');
                var v = enfants(c, 'v')[0];
                var valeur = '';
                if (type === 'inlineStr') {
                    valeur = tous(c, 't').map(function (t) { return t.textContent; }).join('');
                } else if (v) {
                    var brut = v.textContent;
                    if (type === 's') valeur = partages[parseInt(brut, 10)] || '';
                    else if (type === 'b') valeur = brut === '1' ? 'Oui' : 'Non';
                    else if (type === 'e') valeur = '';                          // #N/A, #REF!... : traité comme vide
                    else if (type === 'str') valeur = brut;
                    else valeur = estDate[parseInt(attr(c, 's') || '0', 10)] ? dateExcel(brut) : nombre(brut);
                }
                while (ligne.length < col) ligne.push('');
                ligne[col] = String(valeur);
                if (String(valeur).trim() !== '') vide = false;
            }
            if (!vide) sortie.push(ligne);
        }
        return sortie;
    }

    async function lireExcel(buffer) {
        var type = typeDeFichier(buffer);
        if (type === 'xls') {
            throw new Error('Ce fichier est au très ancien format Excel (.xls), ou protégé par un mot de passe. Ouvrez-le dans Excel et enregistrez-le au format .xlsx (ou CSV), sans mot de passe.');
        }
        if (type !== 'xlsx') throw new Error('Ce fichier n\'est pas un classeur Excel.');
        var zip = lireZip(buffer);
        var classeur = await extraire(zip, 'xl/workbook.xml');
        if (!classeur) throw new Error('Ce fichier n\'est pas un classeur Excel (.xlsx).');

        // Feuilles dans l'ordre du classeur, avec leur fichier ; les feuilles masquées sont sautées.
        var liens = {};
        var relsTexte = await extraire(zip, 'xl/_rels/workbook.xml.rels');
        if (relsTexte) tous(xml(relsTexte), 'Relationship').forEach(function (rel) { liens[attr(rel, 'Id')] = attr(rel, 'Target'); });
        var feuilles = tous(xml(classeur), 'sheet').filter(function (s) { return !/hidden/i.test(attr(s, 'state') || ''); })
            .map(function (s, i) {
                var id = s.getAttributeNS('http://schemas.openxmlformats.org/officeDocument/2006/relationships', 'id') || attr(s, 'r:id');
                var cible = liens[id];
                if (!cible) cible = 'worksheets/sheet' + (i + 1) + '.xml';
                var chemin = cible.charAt(0) === '/' ? cible.slice(1) : 'xl/' + cible.replace(/^\.\//, '');
                return chemin;
            });
        if (!feuilles.length) throw new Error('Ce classeur ne contient aucune feuille visible.');

        var partages = chaines(await extraire(zip, 'xl/sharedStrings.xml'));
        var estDate = stylesDates(await extraire(zip, 'xl/styles.xml'));
        for (var i = 0; i < feuilles.length; i++) {
            var texte = await extraire(zip, feuilles[i]);
            if (!texte) continue;
            var lignes = lignesFeuille(texte, partages, estDate);
            if (lignes.length) return lignes;
        }
        return [];
    }

    window.lireExcel = lireExcel;
    window.typeDeFichier = typeDeFichier;
})();
