"""Production HTTP contract, including requests forwarded from Vercel."""
import unittest
from unittest import mock

try:
    from bench.api import app
except ModuleNotFoundError as error:
    if error.name != 'flask':
        raise
    app = None


@unittest.skipIf(app is None, 'Install requirements-serve.txt for production API tests')
class ProductionAPITests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health_accepts_public_host(self):
        response = self.client.get('/api/health', base_url='https://example.up.railway.app')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'ok'})
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_vercel_origin_can_score_sample(self):
        sample = self.client.get('/api/sample').json
        response = self.client.post('/api/predict', json={'logs': sample['logs'], 'model': 'rules'},
                                    base_url='https://example.up.railway.app',
                                    headers={'Origin': 'https://example.vercel.app'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['rows'])
        self.assertEqual(response.json['model'], 'rules')

    def test_errors_are_json(self):
        cases = [('/api/predict', {'json': {'logs': 'bad'}}, 400),
                 ('/api/predict', {'data': '{', 'content_type': 'application/json'}, 400),
                 ('/api/predict', {'data': 'text'}, 415),
                 ('/missing', {'json': {}}, 404)]
        for path, kwargs, expected in cases:
            with self.subTest(path=path, expected=expected):
                response = self.client.post(path, **kwargs)
                self.assertEqual(response.status_code, expected)
                self.assertIn('error', response.json)

    def test_upload_limit(self):
        with mock.patch.dict(app.config, MAX_CONTENT_LENGTH=16):
            response = self.client.post('/api/predict', json={'logs': 'x' * 100})
        self.assertEqual(response.status_code, 413)
        self.assertIn('error', response.json)

    def test_status_without_models(self):
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as folder, mock.patch('bench.dashboard.STORE', Path(folder)):
            response = self.client.get('/api/status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual([m['id'] for m in response.json['models'] if m['available']], ['rules'])
