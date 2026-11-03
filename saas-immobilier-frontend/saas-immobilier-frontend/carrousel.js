/* Défilement des photos d'un bien : flèches, glissement au doigt ou à la molette, touches ← →.
 * Utilisé par les pages Biens, Matching et Propositions.
 *
 * <Carrousel couverture={data URL de la 1re photo} nombre={nombre de photos}
 *            charger={() => Promise<liste de data URL>} max={facultatif} alt="..." />
 *
 * Seule la couverture est affichée au départ ; les autres photos se chargent quand on
 * touche la carte (survol, doigt, focus ou flèche), pour ne pas alourdir la page. */
(function () {
    var h = React.createElement;

    function Carrousel(props) {
        var nombre = props.nombre || (props.couverture ? 1 : 0);
        var total = Math.min(props.max || 99, nombre);
        var etat = React.useState(null), images = etat[0], setImages = etat[1];
        var rangEtat = React.useState(0), rang = rangEtat[0], setRang = rangEtat[1];
        var piste = React.useRef(null);
        var lance = React.useRef(false);

        if (!props.couverture || total < 1) return null;

        var charger = function () {
            if (lance.current || total < 2 || !props.charger) return;
            lance.current = true;
            Promise.resolve(props.charger()).then(function (liste) {
                if (Array.isArray(liste) && liste.length) setImages(liste.slice(0, total));
            }).catch(function () { lance.current = false; });
        };

        var aller = function (cible) {
            var p = piste.current;
            if (!p) return;
            var k = Math.max(0, Math.min(total - 1, cible));
            p.scrollTo({ left: k * p.clientWidth, behavior: 'smooth' });
            setRang(k);
            charger();
        };

        var surDefilement = function (e) {
            var p = e.currentTarget;
            if (!p.clientWidth) return;
            var k = Math.round(p.scrollLeft / p.clientWidth);
            if (k !== rang) setRang(k);
        };

        var surTouche = function (e) {
            if (e.key === 'ArrowRight') { e.preventDefault(); aller(rang + 1); }
            else if (e.key === 'ArrowLeft') { e.preventDefault(); aller(rang - 1); }
        };

        var vues = [];
        for (var i = 0; i < total; i++) {
            var src = i === 0 ? props.couverture : (images && images[i]);
            vues.push(h('div', { className: 'carrousel-vue', key: i },
                src ? h('img', { src: src, alt: (props.alt || 'Photo du bien') + ' (' + (i + 1) + '/' + total + ')',
                                 draggable: false, loading: 'lazy' })
                    : h('span', null, 'Chargement…')));
        }

        var fleche = function (sens) {
            return h('button', {
                type: 'button',
                className: 'carrousel-fleche ' + (sens < 0 ? 'gauche' : 'droite'),
                'aria-label': sens < 0 ? 'Photo précédente' : 'Photo suivante',
                onClick: function (e) { e.preventDefault(); e.stopPropagation(); aller(rang + sens); }
            }, sens < 0 ? '‹' : '›');
        };

        return h('div', {
            className: 'carrousel' + (props.className ? ' ' + props.className : ''),
            onPointerEnter: charger, onTouchStart: charger, onFocus: charger
        },
            h('div', {
                className: 'carrousel-piste', ref: piste, onScroll: surDefilement,
                tabIndex: total > 1 ? 0 : undefined, onKeyDown: surTouche,
                role: 'group', 'aria-roledescription': 'carrousel',
                'aria-label': (props.alt || 'Photos du bien') + ' : ' + total + ' photo' + (total > 1 ? 's' : '')
            }, vues),
            total > 1 && rang > 0 && fleche(-1),
            total > 1 && rang < total - 1 && fleche(1),
            total > 1 && h('span', { className: 'carrousel-compteur', 'aria-hidden': 'true' }, (rang + 1) + ' / ' + total)
        );
    }

    window.Carrousel = Carrousel;
})();
