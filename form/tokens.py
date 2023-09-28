from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int, int_to_base36

class ComplexTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        """
        Generate a hash value for the given user.
        """
        # Generate a random token using Django's secret key
        secret_key = self.secret
        token = f"{secret_key}-{user.email}"

        return token

complex_token_generator = ComplexTokenGenerator()
