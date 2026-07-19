from django.test import SimpleTestCase

from integrations.adapters.demo import DemoAdapter
from integrations.registry import load_adapter


class RegistryTests(SimpleTestCase):
    def test_loads_adapter_from_dotted_path(self):
        adapter = load_adapter("integrations.adapters.demo.DemoAdapter")
        self.assertIsInstance(adapter, DemoAdapter)
