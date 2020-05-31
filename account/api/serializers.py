from rest_framework import serializers
from account.models import Account, RegistrationVerifiy, generate_key
from rest_framework.authtoken.serializers import AuthTokenSerializer
from django.contrib.auth import authenticate
from django.utils import timezone
from datetime import timedelta
class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password',},write_only=True)
    class Meta:
        model = Account
        fields = ('email','password','password2')
        extra_kwargs = {
            'password' : {'write_only':True}
        }

    def save(self):
        account = Account(
                email = self.validated_data['email'],
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password':'passwords didn\'t match.'}) 
        account.set_password(password)
        account.save()
        return account

class ExpiringAuthTokenSerializer(AuthTokenSerializer):
    username = None
    email = serializers.CharField(
        label=("email"),
        write_only=True
    )
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')
        attrs['user'] = user
        return attrs


class RegistrationVerifiySerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length = 30,
        label = 'email',
        write_only = True,
    )
    def validate(self,attrs):
        email = attrs.get('email')
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email=email)
            msg = 'Email has been registered.'
            raise serializers.ValidationError({'email':msg})
        return attrs

    def save(self):
        now = timezone.now()
        verification, created = RegistrationVerifiy.objects.update_or_create(
                                                email=self.validated_data['email'],
                                                defaults={
                                                            'token'         : generate_key(),
                                                            'verified'      : False,
                                                            'apply_time'    : now,
                                                            'expire_time'   : now+timedelta(minutes=30)
                                                }
                                            )
        return verification


class ChangePasswordSerializer(serializers.Serializer):
    old                = serializers.CharField(required=True)
    new                = serializers.CharField(required=True)
    new_confirm        = serializers.CharField(required=True)