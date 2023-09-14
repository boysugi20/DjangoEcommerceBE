from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from ecommerce_backend.custom_functions import *
from .models import *
from .serializers import *

class RegistrationAPIView(APIView):
    """
    Registers a new user.
    """
    permission_classes = [AllowAny]
    serializer_class = RegistrationSerializer

    def post(self, request):
        """
        Creates a new User object.
        Username, email, and password are required.
        Returns a JSON web token.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {
                'token': serializer.data.get('token', None),
            },
            status=status.HTTP_201_CREATED,
        )


class LoginAPIView(APIView):
    """
    Logs in an existing user.
    """
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        """
        Checks is user exists.
        Email and password are required.
        Returns a JSON web token.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
    
class LogoutView(APIView):
    """
    Logs out a user by clearing their session or token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Depending on your authentication method, clear the session/token here
        # For example, if using token authentication, you can remove the token:
        request.auth = None
        return Response({'detail': 'Logout successful.'}, status=status.HTTP_200_OK)
    
class ChangePasswordView(APIView):
    """
    Allows a user to change their password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            # Check if the old password is correct
            if not request.user.check_password(serializer.validated_data['old_password']):
                return Response({'detail': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()

            # Update the session authentication hash (if using session-based authentication)
            update_session_auth_hash(request, request.user)

            return Response({'detail': 'Password successfully changed.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ForgotPasswordView(APIView):
    """
    Initiates the password reset process and sends a reset email to the user.
    """
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()

            if user:
                # Generate a password reset token
                token_generator = PasswordResetTokenGenerator()
                reset_token = token_generator.make_token(user)

                # Send an email with the reset link
                send_reset_email(user.email, reset_token)

            return Response({'detail': 'Password reset email sent if the email exists.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)