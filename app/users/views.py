# from django.shortcuts import render
# from django.http import JsonResponse
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
#
# from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from rest_framework_simplejwt.views import TokenObtainPairView
# from django.contrib.auth import authenticate
# from rest_framework import generics
# from .models import User
# from rest_framework import status
# from rest_framework_simplejwt.tokens import RefreshToken
#
# # Create your views here.
#
# class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
#     @classmethod
#     def get_token(cls, user):
#         token = super().get_token(user)
#
#         # Add custom claims
#         token['username'] = user.username
#         # ...
#
#         return token
#
# class MyTokenPairView(TokenObtainPairView):
#     serializer_class = MyTokenObtainPairSerializer
#
# @api_view(['GET'])
# def getRoutes(request):
#     routes = [
#         '/api/token',
#         '/api/token/refresh'
#     ]
#     return Response(routes)

# users/views.py

from rest_framework import generics
from users.models import User, Role, Role_User, Access_Token
from users.serializers import UserSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from users.models import User
from users.serializers import UserSerializer
from users.libs.decorators.role import user_role_required
from django.db import transaction


from rest_framework_simplejwt.tokens import AccessToken

class MyAccessToken(AccessToken):
    def encode(self, payload, *args, **kwargs):
        payload['token_type'] = 'access'
        return super().encode(payload, *args, **kwargs)

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user, role_name):
        token = super().get_token(user)
        # token = MyAccessToken(token)
        custom_token = RefreshToken().access_token
        custom_token['username'] = user.username
        custom_token['role'] = role_name
        custom_token['exp'] = token['exp']  # Copy expiration from the original token
        custom_token['user_id'] = user.id


        return custom_token
        # return token


# Register Class
class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        default_role = Role.objects.get(name='User')  # Assuming 'User' is a valid role name
        Role_User.objects.create(user=user, role=default_role)

        refresh = RefreshToken.for_user(user)

        access_token = MyTokenObtainPairSerializer().get_token(user, default_role.name)
        with transaction.atomic():
            Access_Token.objects.create(
                user=user,
                access_token=str(access_token),
                is_blacklisted=False
            )
        response_data = {
            'user_id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'access_token': str(access_token),
            'refresh_token': str(refresh),
        }

        return Response(response_data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        return serializer.save()


# Login Class
class UserLoginView(APIView):
    # permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        # Authenticate user
        user = self.custom_authenticate(email=email, password=password)

        if user:
            role_name = self.get_user_role_name(user.id)
            refresh = RefreshToken.for_user(user)


            access_token = MyTokenObtainPairSerializer().get_token(user, role_name)

            #make every other token blacklisted
            Access_Token.objects.filter(user=user).update(is_blacklisted=True)

            #make current active
            with transaction.atomic():
                Access_Token.objects.create(
                    user=user,
                    access_token=str(access_token),
                    is_blacklisted=False
                )

            response_data = {
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'access_token': str(access_token),
                'refresh_token': str(refresh),
            }

            return Response(response_data, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    def custom_authenticate(self, email, password):
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return None

        if user.check_password(password):
            return user
        else:
            return None

    def get_user_role_name(self, user_id):
        try:
            role_id = Role_User.objects.get(user_id=user_id).role_id
            role_name = Role.objects.get(id=role_id).name
            return role_name
        except Role_User.DoesNotExist:
            return 'DefaultRole'


class LogoutView(APIView):
    def post(self, request):
        # Extract the refresh token from the request
        refresh_token = request.data.get('refresh_token')

        # Validate the refresh token and blacklist it
        if refresh_token:
            try:
                refresh_token = RefreshToken(refresh_token)
                user_id = refresh_token['user_id']
                user = User.objects.get(pk=user_id)
                refresh_token.blacklist()
                Access_Token.objects.filter(user=user).update(is_blacklisted=True)

                return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)
            except Exception as e:
                # Handle token validation errors
                return Response({'detail': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'detail': 'Refresh token not provided'}, status=status.HTTP_400_BAD_REQUEST)


class MyProfileView(APIView):
    @user_role_required
    def get(self, request):
        user_serializer = UserSerializer(request.user)
        return Response(user_serializer.data)
