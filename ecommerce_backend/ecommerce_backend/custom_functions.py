from django.core.mail import send_mail
from django.urls import reverse

def send_reset_email(email, reset_token):
    """
    Send a password reset email to the user.
    """
    subject = 'Password Reset'
    message = f'You have requested a password reset. Click the link below to reset your password:\n\n'
    message += f'Reset Password Link: {reverse("password-reset-confirm", args=[reset_token])}\n\n'
    message += 'If you did not request this password reset, please ignore this email.\n'

    from_email = 'your_email@example.com'  # Replace with your email address
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)