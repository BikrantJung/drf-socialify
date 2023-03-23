from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework import serializers


from .backend import EmailBackend
from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['email', 'username', 'display_name', 'password',
                  ]
        """
        Write only True means django cannot send this data to the user on GET request.
        Only Write this data to database but cannot retrieve
        """

        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):

        return attrs

    def create(self, validate_data):
        return User.objects.create_user(**validate_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'display_name']


class ChangePasswordSerializer(serializers.Serializer):
    # email = serializers.EmailField(max_length=255)

    old_password = password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2', 'old_password']

    def validate(self, attrs):
        user = self.context.get('user')
        if user:
            serialized_user = UserProfileSerializer(user)
            email = serialized_user.data.get('email')
            print("User from validator", user)

            old_password = attrs.get('old_password')
            password = attrs.get('password')
            password2 = attrs.get('password2')

            authenticated = EmailBackend().authenticate(
                email=email, password=old_password)

            if not authenticated:
                raise serializers.ValidationError(
                    {'errors': {'message': 'Incorrect old password!'}})

            if password != password2:
                raise serializers.ValidationError(
                    {'errors': {'message': 'Password and confirm password do not match'}})

            if old_password == password:
                raise serializers.ValidationError(
                    {'errors': {'message': 'Old password and new password must not be same'}})

            user.set_password(password)
            user.save()

        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))

            password_reset_token = PasswordResetTokenGenerator().make_token(user)

            link = 'http://localhost:3000/reset-password/' + uid + '/' + password_reset_token

            print("Password reset link", link)

            # * Send email here
            email_data = {
                'email_subject': 'Password Reset Link',
                'email_body': link,
                'user_email': email
            }
            Util.send_email(email_data)
        else:
            raise serializers.ValidationError({'errors': {'message': ''}})

        return attrs


class PasswordResetSerializer(serializers.Serializer):

    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            uid = self.context.get('uid')
            print("UID===>", uid)
            password_reset_token = self.context.get('password_reset_token')
            password = attrs.get('password')
            password2 = attrs.get('password2')
            if password != password2:
                raise serializers.ValidationError(
                    {'errors': {'message': 'Password and confirm password do not match'}})

            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, password_reset_token):
                raise serializers.ValidationError(
                    {'errors': {'message': 'Invalid or expired token'}})
            user.set_password(password)
            user.save()
            return attrs

        except DjangoUnicodeDecodeError as identifier:
            raise serializers.ValidationError(
                {'errors': {'message': 'Invalid or expired token'}})
