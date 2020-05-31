import binascii
import os
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db.models.signals import post_save
from django.conf import settings
from django.dispatch import receiver
from datetime import datetime, timedelta
from django.utils import timezone

# Create your models here.


def generate_key():
    return binascii.hexlify(os.urandom(20)).decode()

class AccountManager(BaseUserManager):
    def create_user(self,email,password=None):
        if not email:
            raise ValueError("Input an email address.")
        user = self.model(
                email=self.normalize_email(email)
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self,email,password):
        user = self.create_user(
            email = self.normalize_email(email),
            password = password
        )
        user.is_staff = True
        user.group = 0
        user.save(using=self._db)
        return user

class Account(AbstractBaseUser):
    email                   = models.EmailField(verbose_name="email", max_length=30, unique=True)
    date_joined             = models.DateTimeField(verbose_name='date joined', auto_now_add=True)
    last_login              = models.DateTimeField(verbose_name='last login', auto_now=True)
    is_active               = models.BooleanField(default=True)
    is_staff                = models.BooleanField(default=False)
    group                   = models.IntegerField(default=1)

    USERNAME_FIELD = 'email'

    objects = AccountManager()
    def __str__(self):
        return self.email
    # For checking permissions. to keep it simple all admin have ALL permissons
    def has_perm(self, perm, obj=None):
        return self.group == 0

    # Does this user have permission to view this app? (ALWAYS YES FOR SIMPLICITY)
    def has_module_perms(self, app_label):
        return True

class RegistrationVerifiy(models.Model):
    email                   = models.EmailField(verbose_name='email',max_length=30,primary_key=True)
    apply_time              = models.DateTimeField(verbose_name='apply_time',auto_now_add=True)
    expire_time             = models.DateTimeField(verbose_name='expire_time',default=str(timezone.now()+timedelta(minutes=30)))
    token                   = models.CharField(verbose_name='token',max_length=40,unique=True,default=generate_key())
    verified                = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'RegistrationVerifiy'

    def __str__(self):
        return self.token


class ExpiringToken(models.Model):
    key = models.CharField(("Key"), max_length=40, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='auth_exp_token',
        on_delete=models.CASCADE, verbose_name=("User"),
        primary_key=True
    )
    created = models.DateTimeField(("Created"), auto_now_add=True)
    expire_time = models.DateTimeField(("expire_time"), default=str(timezone.now()+timedelta(minutes=30)))
    class Meta:
        verbose_name = ("ExpiringToken")
        verbose_name_plural = ("ExpiringTokens")

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = generate_key()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.key

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        ExpiringToken.objects.create(user=instance)