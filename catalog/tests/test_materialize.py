from django.test import SimpleTestCase

from catalog.services.materialize import _validation_outcome


class ValidationOutcomeTests(SimpleTestCase):
    def test_validation_outcome_aliases(self):
        aliases = (
            ("pass", "passed"),
            ("success", "passed"),
            ("fail", "failed"),
            ("incomplete", "partial"),
        )

        for source, expected in aliases:
            with self.subTest(source=source):
                self.assertEqual(_validation_outcome(source), expected)
