import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from bench import model_store


class ModelStoreTests(unittest.TestCase):
    def test_empty_volume_uses_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, MODEL_STORE=directory):
                self.assertEqual(model_store.model_store(), model_store.BUNDLED)

    def test_partial_custom_store_is_not_mixed_with_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'gmm.pkl').touch()
            with mock.patch.dict(os.environ, MODEL_STORE=directory):
                self.assertEqual(model_store.model_store(), Path(directory))
