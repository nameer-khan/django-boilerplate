# users/serializers.py
from rest_framework import serializers
from users.models import User
from django.utils import timezone
from django.contrib.auth.hashers import make_password



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'username', 'password', 'date_joined')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        # Set date_joined to the current date and time
        validated_data['date_joined'] = timezone.now()
        validated_data['password'] = make_password(validated_data.get('password'))
        user = super().create(validated_data)
        return user
