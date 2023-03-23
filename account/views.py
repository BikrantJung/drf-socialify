from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from account.serializers import UserLoginSerializer, UserRegistrationSerializer

from rest_framework_simplejwt.tokens import RefreshToken
from .backend import EmailBackend
# Create your views here.


def generate_token(user):
    tokens = RefreshToken.for_user(user)

    return {
        "refresh_token": str(tokens),
        "access_token": str(tokens.access_token)
    }


class UserListView(APIView):
    def get(self, req):
        return Response({'Hello': 'User'})


class UserRegistrationView(APIView):
    def post(self, req):
        serializer = UserRegistrationSerializer(data=req.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'Registration Successful'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):

    def post(self, req):
        print("LOGIN REQ", req.data)
        serializer = UserLoginSerializer(data=req.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = EmailBackend().authenticate(email=email, password=password)
            if user is not None:
                tokens = generate_token(user)
                return Response(tokens, status=status.HTTP_200_OK)

            return Response({'errors': {'message': 'Credentials Incorrect'}}, status=status.HTTP_400_BAD_REQUEST)
        """
        The below return is not required since the exception is already raised on serializer.is_valid()
        """
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
