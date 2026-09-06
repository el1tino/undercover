"""Unit tests for the optional scikit-learn phishing classifier.

The classifier gracefully degrades when scikit-learn isn't installed
(matching undercover.dlp.ner's approach for spaCy), so this file has two
paths: one that exercises the skip-reason behavior (always runs) and one
that trains and predicts for real (only runs when scikit-learn is
installed, e.g. `pip install -e ".[phishing,dev]"`).
"""

import pytest

from undercover.phishing.classifier import PhishingClassifier, is_available


@pytest.mark.skipif(is_available(), reason="scikit-learn is installed")
class TestUnavailable:
    def test_not_ready_and_reports_reason(self):
        clf = PhishingClassifier()
        assert clf.is_ready() is False
        assert clf.skip_reason() is not None

    def test_predict_proba_returns_none(self):
        clf = PhishingClassifier()
        assert clf.predict_proba("anything") is None


@pytest.mark.skipif(not is_available(), reason="scikit-learn is not installed")
class TestAvailable:
    def test_trains_on_bundled_dataset_and_is_ready(self):
        clf = PhishingClassifier()
        assert clf.is_ready() is True
        assert clf.skip_reason() is None

    def test_scores_obvious_phishing_higher_than_obvious_ham(self):
        clf = PhishingClassifier()
        phishing_score = clf.predict_proba(
            "Your account has been suspended due to unusual activity. "
            "Verify your account immediately or it will be closed."
        )
        ham_score = clf.predict_proba(
            "Hi team, attaching the agenda for tomorrow's standup meeting."
        )
        assert phishing_score is not None and ham_score is not None
        assert phishing_score > ham_score

    def test_save_and_load_round_trip(self, tmp_path):
        from undercover.phishing.classifier import save_model, load_model, train

        pipeline = train()
        model_path = tmp_path / "model.joblib"
        save_model(pipeline, model_path)
        loaded = load_model(model_path)

        clf = PhishingClassifier(model_path=model_path)
        assert clf.is_ready() is True
        assert loaded.predict(["test"])[0] in {"phishing", "ham"}
