#!/usr/bin/env python3
"""Prépare Stripe pour Zelyro : produits, tarifs, TVA, espace de gestion client, webhook.

À lancer UNE fois, depuis votre ordinateur, d'abord en mode TEST :

    pip install stripe
    export STRIPE_SECRET_KEY=sk_test_...        # clé secrète du mode test (Développeurs > Clés API)
    python3 stripe_setup.py --webhook-url https://saas-immobilier-921a.onrender.com/stripe/webhook

Le script est sans danger à relancer : ce qui existe déjà n'est pas recréé.
Il affiche à la fin les variables à copier dans Render (onglet Environment).
Pour le mode réel, relancez-le avec la clé sk_live_... et l'option --live.

Rien n'est écrit dans la base de Zelyro ; la clé secrète ne quitte pas votre ordinateur.
"""
import argparse
import os
import sys

try:
    import stripe
except ImportError:
    sys.exit("Installez d'abord le paquet : pip install stripe")

SITE = "https://www.zelyro.fr"

# (code du forfait, nom, mensuel, mensuel engagé 12 mois, annuel prépayé), en euros HT.
# Identique à la page tarifs.html : si vous changez un prix là-bas, changez-le ici
# et relancez le script (un nouveau tarif est créé, l'ancien reste pour les abonnés actuels).
FORFAITS = (
    ("essentiel", "Essentiel", 79, 75, 853),
    ("agence", "Agence", 199, 189, 2149),
    ("reseau", "Réseau", 449, 427, 4849),
)
PRIX_SIEGE = 15  # compte utilisateur supplémentaire, € HT / mois
EVENEMENTS_WEBHOOK = [
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_failed",
]


def produit(nom, code):
    for p in stripe.Product.list(active=True, limit=100).auto_paging_iter():
        if (p.metadata or {}).get("zelyro") == code:
            return p.id
    return stripe.Product.create(name=nom, metadata={"zelyro": code}).id


def tarif(produit_id, cle, euros, intervalle, libelle):
    existant = stripe.Price.list(lookup_keys=[cle], active=True, limit=1).to_dict().get("data")
    if existant:
        if existant[0]["unit_amount"] != euros * 100:
            print(f"  ! {cle} existe déjà à {existant[0]['unit_amount'] / 100:g} € (voulu : {euros} €). "
                  "Désactivez-le dans Stripe puis relancez pour le recréer.")
        else:
            print(f"  = {cle} (déjà là)")
        return
    stripe.Price.create(product=produit_id, unit_amount=euros * 100, currency="eur",
                        recurring={"interval": intervalle}, lookup_key=cle, nickname=libelle,
                        tax_behavior="exclusive")
    print(f"  + {cle} : {euros} € HT / {'an' if intervalle == 'year' else 'mois'}")


def taux_tva():
    for t in stripe.TaxRate.list(active=True, limit=100).auto_paging_iter():
        if t.display_name == "TVA" and float(t.percentage) == 20.0 and not t.inclusive and t.country == "FR":
            return t.id
    return stripe.TaxRate.create(display_name="TVA", percentage=20, inclusive=False, country="FR",
                                 jurisdiction="FR", description="TVA 20 %").id


def portail(variante, avec_resiliation):
    for c in stripe.billing_portal.Configuration.list(active=True, limit=100).auto_paging_iter():
        if (c.metadata or {}).get("zelyro") == variante:
            return c.id
    fonctions = {
        "customer_update": {"enabled": True, "allowed_updates": ["name", "email", "address", "phone", "tax_id"]},
        "invoice_history": {"enabled": True},
        "payment_method_update": {"enabled": True},
        "subscription_cancel": {"enabled": False},
    }
    if avec_resiliation:
        fonctions["subscription_cancel"] = {
            "enabled": True, "mode": "at_period_end",
            "cancellation_reason": {"enabled": True, "options": ["too_expensive", "missing_features", "switched_service",
                                                                  "unused", "other"]},
        }
    return stripe.billing_portal.Configuration.create(
        business_profile={"headline": "Zelyro : votre abonnement, vos factures et votre moyen de paiement.",
                          "privacy_policy_url": f"{SITE}/confidentialite.html",
                          "terms_of_service_url": f"{SITE}/cgu.html"},
        features=fonctions, metadata={"zelyro": variante}).id


def webhook(url):
    for w in stripe.WebhookEndpoint.list(limit=100).auto_paging_iter():
        if w.url == url:
            return w.id, None
    w = stripe.WebhookEndpoint.create(url=url, enabled_events=EVENEMENTS_WEBHOOK,
                                      description="Zelyro : abonnements")
    return w.id, w.secret


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--webhook-url", help="adresse publique de /stripe/webhook (crée le webhook)")
    ap.add_argument("--live", action="store_true", help="autorise une clé sk_live_ (mode réel)")
    args = ap.parse_args()

    cle = (os.getenv("STRIPE_SECRET_KEY") or "").strip()
    if not cle.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
        sys.exit("Définissez STRIPE_SECRET_KEY avec votre clé secrète Stripe (sk_test_... pour commencer).")
    if "_live_" in cle and not args.live:
        sys.exit("C'est une clé du mode RÉEL. Relancez avec --live si c'est voulu.")
    stripe.api_key = cle
    print("Mode :", "RÉEL" if "_live_" in cle else "test")

    print("Tarifs des forfaits")
    for code, nom, mensuel, engage, annuel in FORFAITS:
        pid = produit(f"Zelyro {nom}", code)
        tarif(pid, f"zelyro_{code}_mensuel", mensuel, "month", f"{nom}, mensuel sans engagement")
        tarif(pid, f"zelyro_{code}_engage", engage, "month", f"{nom}, mensuel engagé 12 mois (-5 %)")
        tarif(pid, f"zelyro_{code}_annuel", annuel, "year", f"{nom}, annuel prépayé (-10 %)")
    print("Compte supplémentaire")
    tarif(produit("Zelyro, compte utilisateur supplémentaire", "siege"), "zelyro_siege_mensuel", PRIX_SIEGE, "month",
          "Compte utilisateur supplémentaire")

    print("TVA 20 % et espaces de gestion client")
    tva = taux_tva()
    flex = portail("flex", True)
    engage = portail("engage", False)

    env = [("STRIPE_SECRET_KEY", "(la clé que vous venez d'utiliser : sk_test_... ou sk_live_...)"),
           ("STRIPE_TAX_RATE_ID", tva), ("STRIPE_PORTAL_CONFIG_FLEX", flex), ("STRIPE_PORTAL_CONFIG_ENGAGE", engage)]
    if args.webhook_url:
        wid, secret = webhook(args.webhook_url)
        env.append(("STRIPE_WEBHOOK_SECRET", secret or "(webhook déjà créé : Stripe > Développeurs > Webhooks > "
                                                       "votre endpoint > Clé de signature, commence par whsec_)"))
    else:
        env.append(("STRIPE_WEBHOOK_SECRET", "(relancez avec --webhook-url, ou créez le webhook à la main)"))
    print("\nÀ copier dans Render (Environment), puis redéployer :\n")
    for k, v in env:
        print(f"{k}={v}")
    print("\nFRONTEND_URL doit déjà être défini (adresse du site, sans / final).")


if __name__ == "__main__":
    main()
