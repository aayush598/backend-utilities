import unittest
from flask_testing import TestCase
from app import app

class MyTest(TestCase):

    def create_app(self):
        # Configure your app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        return app

    def test_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello, World!', response.data)

    def test_login_get(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login Page', response.data)

    def test_login_post_success(self):
        response = self.client.post('/login', data=dict(username='admin', password='admin'))
        self.assertEqual(response.status_code, 302)  # Redirects to index

    def test_login_post_failure(self):
        response = self.client.post('/login', data=dict(username='admin', password='wrongpassword'))
        self.assertEqual(response.status_code, 401)
        self.assertIn(b'Invalid credentials', response.data)

if __name__ == '__main__':
    unittest.main()
