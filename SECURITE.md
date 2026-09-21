# Zelyro — sécurisation : ce qui change et comment déployer

Ce document est destiné à Hugo (accès Render) et Tom (accès GitHub et Vercel).
Les modifications ont été testées sur une vraie base PostgreSQL (54 tests automatisés,
plus un essai avec gunicorn et 4 workers). Rien n'est en ligne tant que les fichiers
ne sont pas poussés sur GitHub.

## Urgent, à faire tout de suite, sans attendre le déploiement

1. Ouvrir Render, onglet Environment du service backend, et regarder si SECRET_KEY existe.
   Si elle n'existe pas, l'ancien code utilise la valeur publique "your-secret-key-change-in-production",
   ce qui permettrait à n'importe qui de fabriquer un jeton de connexion valide pour n'importe quel compte.
   Dans ce cas, créer SECRET_KEY maintenant (l'ancien code la lit déjà) avec une valeur générée par :
   `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
   Conséquence : tout le monde devra se reconnecter une fois. C'est normal.
2. Vérifier si le compte de test existe en production (mot de passe connu publiquement : password123) :
   `SELECT id, email FROM users WHERE email = 'test@example.com';`
   S'il existe, ne pas le supprimer à l'aveugle : les 33 leads de démonstration sont rattachés à user_id = 1,
   qui peut être ce compte ou un vrai utilisateur. Vérifier d'abord avec
   `SELECT user_id, count(*) FROM leads GROUP BY user_id;` puis, si le compte de test est bien seul concerné,
   `DELETE FROM users WHERE email = 'test@example.com';` (supprimer ses leads avant si la base ne le fait pas en cascade).
   S'il s'agit d'un vrai compte, changer simplement son mot de passe.

## Ce qui a changé dans le backend (app.py)

- Clé secrète obligatoire (32 caractères minimum). Sans elle, l'application refuse de démarrer
  au lieu de tourner avec une clé publique. Si le démarrage échoue sur Render, l'ancienne version
  reste en service : rien ne casse pour les utilisateurs.
- Routes supprimées : /api/v1/init-db (publique, permettait à n'importe qui de toucher à la base)
  et /api/v1/debug-cle (affichait le début de la clé Anthropic). Le compte test@example.com / password123
  n'est plus créé. Les données de démonstration se créent uniquement à la main :
  `python app.py init-db --demo` (mot de passe aléatoire affiché une fois).
- CORS restreint : seuls les sites Zelyro (Vercel de l'équipe immo-flow, localhost et les domaines listés
  dans ALLOWED_ORIGINS) peuvent appeler l'API depuis un navigateur. Avant, tout site web le pouvait.
- Limites de débit : 8 mauvais mots de passe par quart d'heure et par adresse e-mail, 10 inscriptions par heure
  et par IP, 30 extractions par heure par utilisateur (pour protéger la facture Anthropic), 300 requêtes par minute et par IP.
- Connexion : durée de 24 h au lieu de 30 jours, mot de passe de 10 caractères minimum, e-mail insensible
  à la casse (les anciens comptes avec majuscules continuent de fonctionner), même réponse pour un compte
  inconnu et un mauvais mot de passe, jetons sans expiration ou sans identifiant refusés.
- Erreurs : le détail technique (noms de tables, requêtes SQL) reste dans les journaux Render et n'est plus
  renvoyé au navigateur. La clé secrète n'est plus affichée dans les journaux au démarrage.
- Entrées : longueurs et valeurs autorisées vérifiées, corps de requête limité à 128 Ko, en-têtes de sécurité
  sur toutes les réponses de l'API.
- Dépendances mises à jour (Flask 3.1, PyJWT, Werkzeug, gunicorn 23, requests) : les anciennes versions
  avaient des failles connues. Aucune faille connue dans les versions choisies au moment du test.

## Ce qui a changé dans le frontend

- React, Babel, Chart.js et les polices (Inter, Playfair Display) sont désormais dans le dossier vendor/
  au lieu d'être chargés depuis unpkg, cdnjs et Google Fonts. Plus aucun script tiers ne s'exécute dans la page,
  et plus aucune donnée de visiteur n'est envoyée à Google (utile pour le RGPD).
- vercel.json ajoute les en-têtes de sécurité : politique de contenu (le navigateur n'accepte que les scripts du site
  et les appels vers l'API Render), interdiction d'afficher le site dans un cadre (clickjacking), HTTPS forcé,
  pas de fuite d'adresse en Referer.
- Le rendu visuel est identique. Chaque page a été testée avec la politique de contenu activée : aucune erreur.

Important : pour que vercel.json soit pris en compte, le Root Directory du projet Vercel doit être le dossier
saas-immobilier-frontend (Settings, General, Root Directory). Si vous changez l'adresse du backend Render,
mettre à jour connect-src dans vercel.json.

## Ordre de déploiement

1. Render : ajouter ou vérifier SECRET_KEY (voir plus haut). Vérifier aussi DATABASE_URL et ANTHROPIC_API_KEY.
2. GitHub : pousser les fichiers sur une branche séparée (par exemple securite), pas directement sur main.
   Hugo relit app.py.
3. Backend : déployer cette branche sur Render. Vérifier que https://saas-immobilier-921a.onrender.com/health répond,
   puis se connecter depuis le site.
4. Frontend : Vercel crée automatiquement un aperçu de la branche. Tester la connexion, les leads, les biens,
   le dashboard, puis fusionner dans main.
5. Se reconnecter une fois (les anciens jetons de 30 jours ne sont plus acceptés si la clé secrète change).

Si quelque chose ne va pas : Render permet de revenir au déploiement précédent en un clic (Events, Rollback),
et Vercel aussi (Deployments, Promote to Production sur l'ancienne version).

## Variables d'environnement

Voir .env.flask.example dans ce dossier. Seules SECRET_KEY, DATABASE_URL et ANTHROPIC_API_KEY sont nécessaires.
Les autres ont des valeurs par défaut raisonnables.

## À savoir

- Gunicorn tourne avec 4 workers et les compteurs de limites sont en mémoire, propres à chaque worker. Les limites
  sont donc appliquées avec une marge (jusqu'à 4 fois plus d'essais que le chiffre indiqué). Pour des limites exactes,
  ajouter un Redis (Render Key Value) et renseigner RATELIMIT_STORAGE_URI.
- Les limites par adresse IP supposent que Render place la vraie adresse du visiteur en dernier dans X-Forwarded-For
  (TRUSTED_PROXIES=1). Si les inscriptions sont refusées pour tout le monde (429), passer TRUSTED_PROXIES à 2.
- L'extraction envoie le texte des messages de prospects à Anthropic : à mentionner dans la politique de confidentialité.

## Ce qui reste à faire (hors de ce lot)

- Domaine personnalisé (par exemple app.zelyro.fr) : c'est ce qui fait disparaître l'avertissement
  "site potentiellement dangereux" des navigateurs, qui vise très souvent les adresses en vercel.app
  sur lesquelles n'importe qui peut publier. Ajouter ensuite le domaine dans ALLOWED_ORIGINS et connect-src.
- Double authentification sur GitHub, Vercel, Render et le compte Anthropic.
- Politique de confidentialité, mentions légales, contrats de sous-traitance (Render, Vercel, Anthropic), hébergement en UE.
- Précompiler le JSX (Vite) pour retirer 'unsafe-inline' de la politique de contenu, puis passer le jeton
  de connexion dans un cookie httpOnly plutôt que dans le stockage local du navigateur.
- Régénérer la clé Anthropic si elle a été exposée (la route debug-cle en montrait le début) et la coller sans espace ni retour à la ligne.
- Lancer régulièrement `pip-audit -r requirements.txt` pour surveiller les dépendances.
