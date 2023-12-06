import unittest
import requests
import os


total_ran = 0


class ServerTest(unittest.TestCase):
    def test_server_response(self):
        response = requests.get(url="http://localhost:8080")
        if response.status_code:
            response = True
        else:
            response = False
        self.assertEqual(response, True)
    def test_db_presence(self):
        result = os.path.isfile("./totally_not_my_privateKeys.db")
        self.assertEqual(result, True)


class AuthTest(unittest.TestCase):
    def test_auth_get_response(self):
        response = requests.get(
            url="http://localhost:8080/auth", auth=("userABC", "password123")
        )
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_auth_post_response(self):
        response = requests.post(
            url="http://localhost:8080/auth", auth=("userABC", "password123")
        )
        self.assertEqual(
            response.status_code, 200
        )  # assert that the response code is OK

    def test_auth_patch_response(self):
        response = requests.patch(
            url="http://localhost:8080/auth", auth=("userABC", "password123")
        )
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_auth_put_response(self):
        response = requests.put(
            url="http://localhost:8080/auth",
            auth=("userABC", "password123"),
            data={"test": "data"},
        )
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_auth_delete_response(self):
        response = requests.delete(
            url="http://localhost:8080/auth", auth=("userABC", "password123")
        )
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_auth_head_response(self):
        response = requests.head(
            url="http://localhost:8080/auth", auth=("userABC", "password123")
        )
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed


class JWKSTest(unittest.TestCase):
    def test_jwks_get_response(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(
            response.status_code, 200
        )  # assert that the response code is OK

    def test_jwks_post_response(self):
        response = requests.post(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_jwks_patch_response(self):
        response = requests.patch(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_jwks_put_response(self):
        response = requests.put(
            url="http://localhost:8080/.well-known/jwks.json", data={"test": "data"}
        )
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_jwks_delete_response(self):
        response = requests.delete(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed

    def test_jwks_head_response(self):
        response = requests.head(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(
            response.status_code, 405
        )  # assert that the response code is Method Not Allowed


class ResponseTest(unittest.TestCase):
    def test_jwks_response_format(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        for JWK in response.json()["keys"]:
            for item in JWK:
                if item == "alg":
                    self.assertEqual(
                        JWK[item], "RS256"
                    )  # verify that values are set correctly
                elif item == "kty":
                    self.assertEqual(
                        JWK[item], "RSA"
                    )  # verify that values are set correctly
                elif item == "use":
                    self.assertEqual(
                        JWK[item], "sig"
                    )  # verify that values are set correctly
                elif item == "e":
                    self.assertEqual(
                        JWK[item], "AQAB"
                    )  # verify that values are set correctly

    def test_auth_response_format(self):
        response = requests.post(
            url="http://localhost:8080/auth", auth=("userABC", "password123")
        )
        self.assertRegex(
            response.text, r".*\..*\..*"
        )  # assert that it is in [header].[payload].[signature] format


basic_suite = unittest.TestLoader().loadTestsFromTestCase(
    ServerTest
)  # catches only the basic test
auth_suite = unittest.TestLoader().loadTestsFromTestCase(
    AuthTest
)  # catches only the /auth return codes
jwks_suite = unittest.TestLoader().loadTestsFromTestCase(
    JWKSTest
)  # catches only the /.well-known/jwks.json return codes
response_suite = unittest.TestLoader().loadTestsFromTestCase(
    ResponseTest
)  # checks the response formatting for /auth and /.well-known/jwks.json
full_suite = unittest.TestSuite([basic_suite, auth_suite, jwks_suite, response_suite])
unittest.TextTestRunner(verbosity=2).run(full_suite)  # run the full set of tests
print("\nTest Coverage = Lines of Code Executed in Tests / Total Lines of Code")
print("Test Coverage = 144 / 155 = {}%".format(int((144 / 155) * 100)))
# My Test Suite does not cover the following lines of code:
#   86-93: Checking if there is an expired tag
#   98-101: Querying for an expired key
