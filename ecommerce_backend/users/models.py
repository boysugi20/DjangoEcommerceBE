import jwt
from .managers import UserManager

from datetime import datetime
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.core import validators
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin

class User(PermissionsMixin, AbstractBaseUser):
    """
    Defines our custom user class.
    Email and password are required.
    """

    email = models.EmailField(
        validators=[validators.validate_email],
        unique=True,
        blank=False
    )

    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)

    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # The `USERNAME_FIELD` property tells us which field we will use to log in.
    USERNAME_FIELD = 'email'

    # Tells Django that the UserManager class defined above should manage
    # objects of this type.
    objects = UserManager()

    def __str__(self):
        """
        Returns a string representation of this `User`.
        This string is used when a `User` is printed in the console.
        """
        return self.email

    @property
    def token(self):
        """
        Allows us to get a user's token by calling `user.token` instead of
        `user.generate_jwt_token().

        The `@property` decorator above makes this possible. `token` is called
        a "dynamic property".
        """
        return self._generate_jwt_token()

    def _generate_jwt_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 60 days into the future.
        """
        dt = datetime.now() + timedelta(days=60)
        timestamp = int(dt.timestamp())  # Get the Unix timestamp for the expiration

        token = jwt.encode({
            'id': self.pk,
            'exp': timestamp  # Set the expiration using the timestamp
        }, settings.SECRET_KEY, algorithm='HS256')

        return token
