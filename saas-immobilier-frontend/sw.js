/* Service worker de Zelyro : reçoit les notifications (Web Push) et ouvre la
   bonne fiche au clic. Il ne met rien en cache : les données restent toujours
   celles du serveur. */
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });

self.addEventListener('push', function (event) {
    var d = {};
    try { d = event.data ? event.data.json() : {}; } catch (e) { d = {}; }
    var options = {
        body: typeof d.body === 'string' ? d.body : '',
        icon: '/icons/icon-192.png',
        badge: '/icons/badge-96.png',
        data: { url: typeof d.url === 'string' ? d.url : '/dashboard.html' }
    };
    if (typeof d.tag === 'string' && d.tag) { options.tag = d.tag; options.renotify = true; }
    event.waitUntil(self.registration.showNotification(typeof d.title === 'string' && d.title ? d.title : 'Zelyro', options));
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    // Seule une adresse de ce site peut être ouverte, quoi que contienne la notification.
    var cible;
    try {
        var u = new URL((event.notification.data && event.notification.data.url) || '/dashboard.html', self.location.origin);
        cible = u.origin === self.location.origin ? u.href : self.location.origin + '/dashboard.html';
    } catch (e) { cible = self.location.origin + '/dashboard.html'; }
    event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (fenetres) {
        for (var i = 0; i < fenetres.length; i++) {
            if (fenetres[i].url === cible && 'focus' in fenetres[i]) return fenetres[i].focus();
        }
        for (var j = 0; j < fenetres.length; j++) {
            if ('navigate' in fenetres[j] && 'focus' in fenetres[j]) {
                return fenetres[j].navigate(cible).then(function (c) { return c && c.focus(); });
            }
        }
        return self.clients.openWindow(cible);
    }));
});
