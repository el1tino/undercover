"""Optional spaCy-backed detection of unstructured PII (names, addresses, orgs).

spaCy is an optional dependency (install the ``ner`` extra:
``pip install undercover[ner]``) plus a downloaded language model
(``python -m spacy download en_core_web_sm``). Callers that don't need
NER never pay the import cost or need the model installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from spacy.language import Language

# Entity labels (as produced by spaCy's en_core_web_sm) that are treated
# as unstructured PII worth flagging.
PII_ENTITY_LABELS = {
    "PERSON": "Person Name",
    "GPE": "Location",
    "LOC": "Location",
    "FAC": "Address / Facility",
    "ORG": "Organization",
    "NORP": "Nationality / Group",
}

_MODEL_NAME = "en_core_web_sm"
_nlp: Optional["Language"] = None
_load_error: Optional[str] = None


def is_available() -> bool:
    """Return True if spaCy and the language model can be loaded."""
    return _get_pipeline() is not None


def load_error() -> Optional[str]:
    """Return a human-readable reason NER is unavailable, if any."""
    _get_pipeline()
    return _load_error


def _get_pipeline() -> Optional["Language"]:
    global _nlp, _load_error
    if _nlp is not None:
        return _nlp
    if _load_error is not None:
        return None
    try:
        import spacy
    except ImportError:
        _load_error = (
            "spaCy is not installed. Install it with "
            "`pip install undercover[ner]`."
        )
        return None
    try:
        _nlp = spacy.load(_MODEL_NAME)
    except OSError:
        _load_error = (
            f"spaCy model '{_MODEL_NAME}' is not downloaded. Run "
            f"`python -m spacy download {_MODEL_NAME}`."
        )
        return None
    return _nlp


def find_entities(text: str) -> list[dict]:
    """Run NER over ``text`` and return unstructured-PII matches.

    Each result is a dict with ``name``, ``label``, ``value``, ``start``,
    ``end``. Returns an empty list (never raises) if spaCy/the model is
    unavailable -- check :func:`is_available` first to distinguish "no
    matches" from "NER did not run".
    """
    nlp = _get_pipeline()
    if nlp is None:
        return []

    doc = nlp(text)
    results = []
    for ent in doc.ents:
        label = PII_ENTITY_LABELS.get(ent.label_)
        if label is None:
            continue
        results.append(
            {
                "name": ent.label_.lower(),
                "label": label,
                "value": ent.text,
                "start": ent.start_char,
                "end": ent.end_char,
            }
        )
    return results
