
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser


class TimeStampMixin(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class User(AbstractUser, TimeStampMixin):
    pass

class Role(TimeStampMixin, models.Model):
    name = models.CharField(max_length=255)
    status = models.BooleanField(default=True)

class Role_User(TimeStampMixin,models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

class Permission(TimeStampMixin,models.Model):
    scope = models.CharField(max_length=255)

class Permission_Role(TimeStampMixin,models.Model):
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

class Access_Token(TimeStampMixin,models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    access_token = models.TextField(max_length=None)
    is_blacklisted = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Access Token Blacklist'
        verbose_name_plural = 'Access Tokens Blacklist'