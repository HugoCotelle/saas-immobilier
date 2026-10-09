"""Mesure la fiabilité de l'extraction des e-mails de portails, avec le vrai code de Zelyro (app.py).

    python3 evaluer_extraction.py cases.json --sans-ia      # règles seules, sans clé ni coût
    ANTHROPIC_API_KEY=... python3 evaluer_extraction.py cases.json          # règles + IA, un passage
    ANTHROPIC_API_KEY=... python3 evaluer_extraction.py cases.json 3        # 3 passages (stabilité)
    ANTHROPIC_API_KEY=... EXTRACTION_MODEL=claude-haiku-5-5 python3 evaluer_extraction.py cases.json
        # compare un autre modèle avant de le mettre en service (variable EXTRACTION_MODEL chez l'hébergeur)

Les cas ont le format du dossier « Test mail » : {id, email, expected} avec des clés comme contact.email,
contact.phone, contact.last_name, budget_eur, financing, urgency, intent, is_lead_email. Seuls les champs
que Zelyro extrait sont comparés (pas le portail ni la référence de l'annonce).

La base de données n'est pas utilisée. Pas de vrais mails ici : anonymisez avant de les ajouter.
"""
import json, os, re, sys
from collections import defaultdict
from datetime import datetime

os.environ.setdefault("DATABASE_URL", "postgresql://inutile@localhost/inutile")
os.environ.setdefault("SECRET_KEY", "x" * 48)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app

FINANCEMENT = {"accord_bancaire": "approved", "en_cours": "in_progress", "non_precise": None}
URGENCE = {"immediate": "immediate", "trois_mois": "1-3_months", "non_precise": None}


def extraire(email, sans_ia):
    """(champs de l'IA ou None, e-mail final, téléphone final) comme dans _creer_lead_depuis_portail."""
    champs = None
    if not sans_ia:
        consigne = app.CONSIGNE_PORTAIL.format(
            portail="un portail d'annonces", date=datetime.utcnow().strftime('%Y-%m-%d'),
            types=', '.join(app.TYPES_BIEN), activites=', '.join(app.ACTIVITES),
            echeances=', '.join(app.ECHEANCES), financements=', '.join(app.FINANCEMENTS), message=email[:4000])
        champs, erreur = app._appeler_extraction_ia(consigne)
        if erreur:
            raise RuntimeError(erreur[0])
    mail, tel = app._coordonnees_fiables(champs, email)
    return champs, mail, tel


def comparer(cle, attendu, champs, mail, tel):
    """(ok, obtenu) ou None si Zelyro n'extrait pas ce champ (ou sans IA)."""
    if cle == "contact.email":
        return mail == attendu, mail
    if cle == "contact.phone":
        return tel == attendu, tel
    if champs is None:
        return None
    if cle == "is_lead_email":
        return champs.get("est_demande_contact") == attendu, champs.get("est_demande_contact")
    if not champs.get("est_demande_contact", True):
        return None  # mail écarté : les autres champs ne sont pas utilisés
    if cle == "contact.last_name":
        nom = (champs.get("nom") or "").lower()
        return attendu.lower() in nom, champs.get("nom")
    if cle == "budget_eur":
        return champs.get("budget") == attendu, champs.get("budget")
    if cle == "financing":
        if attendu not in FINANCEMENT:
            return None
        return champs.get("financement") == FINANCEMENT[attendu], champs.get("financement")
    if cle == "urgency":
        if attendu not in URGENCE:
            return None
        return champs.get("echeance") == URGENCE[attendu], champs.get("echeance")
    if cle == "intent":
        if attendu not in ("achat", "location"):
            return None
        return champs.get("transaction") == attendu, champs.get("transaction")
    return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sans_ia = "--sans-ia" in sys.argv
    if not args:
        sys.exit(__doc__)
    cas = json.load(open(args[0], encoding="utf-8"))
    passages = int(args[1]) if len(args) > 1 else 1
    if not sans_ia and not (os.getenv("ANTHROPIC_API_KEY") or "").strip():
        sys.exit("ANTHROPIC_API_KEY absente : utilisez --sans-ia pour tester les règles seules.")
    print(f"Modèle : {'aucun (règles seules)' if sans_ia else app.MODELE_EXTRACTION} | {len(cas)} cas x {passages} passage(s)\n")

    par_champ, echecs = defaultdict(lambda: [0, 0]), []
    for c in cas:
        for n in range(passages if not sans_ia else 1):
            try:
                champs, mail, tel = extraire(c["email"], sans_ia)
            except Exception as e:
                echecs.append((c["id"], n, "ERREUR", None, str(e)))
                continue
            for cle, attendu in c["expected"].items():
                r = comparer(cle, attendu, champs, mail, tel)
                if r is None:
                    continue
                ok, obtenu = r
                par_champ[cle][0] += ok
                par_champ[cle][1] += 1
                if not ok:
                    echecs.append((c["id"], n, cle, attendu, obtenu))
    total_ok = sum(v[0] for v in par_champ.values())
    total = sum(v[1] for v in par_champ.values())
    print("Exactitude par champ :")
    for cle, (ok, n) in sorted(par_champ.items(), key=lambda kv: kv[1][0] / kv[1][1]):
        print(f"  {cle:<20} {ok}/{n}  ({100 * ok / n:.0f} %)")
    print(f"\nGlobal : {total_ok}/{total} ({100 * total_ok / max(total, 1):.0f} %)")
    if echecs:
        print("\nÉchecs :")
        for cid, n, cle, attendu, obtenu in echecs:
            print(f"  [{cid} #{n + 1}] {cle} : attendu={attendu!r} obtenu={obtenu!r}")


if __name__ == "__main__":
    main()
