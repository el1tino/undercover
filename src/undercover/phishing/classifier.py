"""Optional scikit-learn classifier for phishing vs. legitimate ("ham") text.

scikit-learn is an optional dependency (install the ``phishing`` extra:
``pip install undercover[phishing]``). Callers that only need the
rule-based checks never pay the import cost, and :class:`PhishingClassifier`
degrades gracefully (no exceptions) when it isn't installed -- the same
pattern :mod:`undercover.dlp.ner` uses for spaCy.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sklearn.pipeline import Pipeline

DEFAULT_DATASET_PATH = Path(__file__).parent / "data" / "sample_dataset.csv"

_load_error: Optional[str] = None
_import_checked = False


def is_available() -> bool:
    """Return True if scikit-learn can be imported."""
    return _check_import() is None


def load_error() -> Optional[str]:
    """Return a human-readable reason the classifier is unavailable, if any."""
    return _check_import()


def _check_import() -> Optional[str]:
    global _load_error, _import_checked
    if _import_checked:
        return _load_error
    _import_checked = True
    try:
        import sklearn  # noqa: F401
    except ImportError:
        _load_error = (
            "scikit-learn is not installed. Install it with "
            "`pip install undercover[phishing]`."
        )
    return _load_error


def load_dataset(path: Path = DEFAULT_DATASET_PATH) -> tuple[list[str], list[str]]:
    """Load a labeled text/label CSV. See docs/phase2-phishing-detection.md
    for the format and where to get a real (non-toy) dataset."""
    texts: list[str] = []
    labels: list[str] = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            texts.append(row["text"])
            labels.append(row["label"])
    return texts, labels


def build_pipeline() -> "Pipeline":
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1),
            ),
            ("clf", LogisticRegression(max_iter=1000)),
        ]
    )


def train(dataset_path: Path = DEFAULT_DATASET_PATH) -> "Pipeline":
    """Train a fresh pipeline on the given dataset and return it (unsaved)."""
    texts, labels = load_dataset(dataset_path)
    pipeline = build_pipeline()
    pipeline.fit(texts, labels)
    return pipeline


def save_model(pipeline: "Pipeline", path: Path) -> None:
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load_model(path: Path) -> "Pipeline":
    import joblib

    return joblib.load(path)


class PhishingClassifier:
    """Predicts a phishing probability for a piece of text.

    If ``model_path`` is given and exists, the pre-trained pipeline is
    loaded from disk. Otherwise a pipeline is trained in-memory on the
    bundled demo dataset -- fine for the small dataset shipped here, but
    a real deployment should train once (``undercover-phish-train``) and
    load the saved model instead of retraining per process.
    """

    def __init__(self, model_path: Optional[Path] = None):
        self._pipeline: Optional["Pipeline"] = None
        self._skip_reason: Optional[str] = None

        if not is_available():
            self._skip_reason = load_error()
            return

        if model_path is not None and Path(model_path).exists():
            self._pipeline = load_model(Path(model_path))
        else:
            self._pipeline = train()

    def is_ready(self) -> bool:
        return self._pipeline is not None

    def skip_reason(self) -> Optional[str]:
        return self._skip_reason

    def predict_proba(self, text: str) -> Optional[float]:
        """Return P(phishing) for ``text``, or None if the model isn't ready."""
        if self._pipeline is None:
            return None
        proba = self._pipeline.predict_proba([text])[0]
        classes = list(self._pipeline.classes_)
        return float(proba[classes.index("phishing")])
