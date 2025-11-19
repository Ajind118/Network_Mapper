import unittest
import main

class FlaskAppTests(unittest.TestCase):

    def setUp(self):
        main.app.testing = True
        self.app = main.app.test_client()

    def test_index_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Network Mapper', response.data)

    def test_visual_page(self):
        response = self.app.get('/visual')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Network Visual Mapper', response.data)

    def test_local_range_api(self):
        response = self.app.get('/api/localrange')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'range', response.data)

    def test_gateway_api(self):
        response = self.app.get('/api/gateway')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'gateway', response.data)

if __name__ == '__main__':
    unittest.main()
