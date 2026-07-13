"""Offline spelling and homograph checks for page text.

Legitimate brands proofread their sites; phishing kits are often full of
misspellings and character-swap tricks. A full multilingual spell-checker is
out of scope for an offline bundle, so this module goes for **high precision,
low recall**: it only flags things it is confident about —

  * a curated table of common phishing-relevant misspellings,
  * homograph tokens (Latin mixed with Cyrillic/Greek look-alikes),
  * absurd character repetition.

Deep, general spelling/grammar review is delegated to the AI pass when a
model key is configured (see :meth:`NvidiaSecurityAI.analyze_phishing`).
"""

import re
import unicodedata

# Misspelling -> correct form. Curated toward words that show up on phishing
# pages (account/security/verification vocabulary).
COMMON_MISSPELLINGS = {
    "acount": "account", "accont": "account", "acccount": "account",
    "verifcation": "verification", "verifiction": "verification",
    "verefication": "verification", "verfiy": "verify", "verifiy": "verify",
    "securty": "security", "securiy": "security", "seucrity": "security",
    "passwrod": "password", "pasword": "password", "passord": "password",
    "loggin": "login", "logn": "login", "signin": "sign in",
    "confrim": "confirm", "confirmm": "confirm", "conform": "confirm",
    "immediatly": "immediately", "immediatley": "immediately",
    "informations": "information", "infomation": "information",
    "recieve": "receive", "recived": "received", "recieved": "received",
    "suspend": "suspended", "suspened": "suspended", "suspeneded": "suspended",
    "unathorized": "unauthorized", "unauthorised": "unauthorized",
    "successfull": "successful", "successfuly": "successfully",
    "notifcation": "notification", "notifiction": "notification",
    "adress": "address", "adres": "address", "billng": "billing",
    "paymnet": "payment", "payement": "payment", "curency": "currency",
    "acess": "access", "accsess": "access", "detials": "details",
    "youre": "your", "acctount": "account", "urgnet": "urgent",
    "expird": "expired", "expiere": "expire", "temporaly": "temporarily",
    "canceld": "cancelled", "clik": "click", "requird": "required",
    "updatd": "updated", "activ": "active", "acctivate": "activate",
    "custmer": "customer", "custommer": "customer", "supprt": "support",
    "athenticate": "authenticate", "athentication": "authentication",
    "pleace": "please", "kindy": "kindly", "garantee": "guarantee",
}

_WORD_RE = re.compile(r"[A-Za-zÀ-ÿА-Яа-яЁёΑ-Ωα-ω]+")
_MIN_TOKEN_LEN = 4

_LATIN_RE = re.compile(r"[A-Za-z]")
_CONFUSABLE_RE = re.compile(r"[А-Яа-яЁёΑ-Ωα-ω]")


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    if name.startswith("LATIN"):
        return "LATIN"
    if name.startswith("CYRILLIC"):
        return "CYRILLIC"
    if name.startswith("GREEK"):
        return "GREEK"
    return "OTHER"


def _is_homograph(token: str) -> bool:
    """A single word mixing Latin with Cyrillic/Greek letters is a red flag."""
    if not (_LATIN_RE.search(token) and _CONFUSABLE_RE.search(token)):
        return False
    scripts = {_script_of(ch) for ch in token if ch.isalpha()}
    scripts.discard("OTHER")
    return len(scripts) > 1


def _has_absurd_repetition(token: str) -> bool:
    return re.search(r"(.)\1\1\1", token) is not None


def analyze_spelling(text: str, max_findings: int = 25) -> dict:
    """Return spelling findings for the given visible page text.

    ``{"misspellings": [...], "homographs": [...], "checked_words": int}``
    """
    misspellings = []
    homographs = []
    seen_miss = set()
    seen_homo = set()
    checked = 0

    for match in _WORD_RE.finditer(text or ""):
        token = match.group(0)
        if len(token) < _MIN_TOKEN_LEN:
            continue
        checked += 1
        lowered = token.lower()

        if _is_homograph(token) and token not in seen_homo:
            seen_homo.add(token)
            homographs.append(token)
        elif lowered in COMMON_MISSPELLINGS and lowered not in seen_miss:
            seen_miss.add(lowered)
            misspellings.append((token, COMMON_MISSPELLINGS[lowered]))
        elif _has_absurd_repetition(lowered) and lowered not in seen_miss:
            seen_miss.add(lowered)
            misspellings.append((token, "excessive character repetition"))

        if len(misspellings) + len(homographs) >= max_findings:
            break

    return {
        "misspellings": misspellings,
        "homographs": homographs,
        "checked_words": checked,
    }
