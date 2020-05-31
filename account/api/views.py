from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.compat import coreapi, coreschema
from rest_framework.schemas import ManualSchema
from rest_framework.schemas import coreapi as coreapi_schema
from account.api.serializers import (
                                        RegistrationSerializer, 
                                        ExpiringAuthTokenSerializer,
                                        ChangePasswordSerializer,
                                        RegistrationVerifiySerializer,
                                    )
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from account.models import ExpiringToken
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from datetime import timedelta
from account.api.authentication import ExpiringTokenAuthentication
from account.models import Account, RegistrationVerifiy
from django.core.mail import send_mail
from django.conf import settings

@api_view(['POST',])
@permission_classes([])
@authentication_classes([])
def registration_view(request,b64info=None):
    data = {}
    try: #get model by token
        decoded_email,token = urlsafe_base64_decode(b64info).decode().split('/')
        verification = RegistrationVerifiy.objects.get(token=token)
        if decoded_email != verification.email:
            raise AttributeError
        #check if token has expired or has been used
        if verification.expire_time < timezone.now() or verification.verified:
            return Response('Token has expired.',status.HTTP_400_BAD_REQUEST)
        verification.verified = True
        serializer = RegistrationSerializer(data={
                                                'email'         : verification.email,
                                                'password'      : request.data['password'],
                                                'password2'     : request.data['password2']
                                            })
        if serializer.is_valid():
            account = serializer.save()
            data['response'] = 'Registration successed.'
            token = ExpiringToken.objects.get(user=account).key
            data['token'] = token
        else:
            data = serializer.errors
        verification.save()
    except RegistrationVerifiy.DoesNotExist:
        return Response({"Invalid token."},status=status.HTTP_400_BAD_REQUEST)
    except AttributeError:
        return Response({"Invalid url."},status=status.HTTP_404_NOT_FOUND)
    return Response(data)

@api_view(['POST',])
@permission_classes([])
@authentication_classes([])
def apply_registration(request):
    #send a verfication mail with a register url.
    data = {}
    email = request.data.get('email','0')
    serializer = RegistrationVerifiySerializer(data=request.data)
    if serializer.is_valid():
        verification = serializer.save()
        b64 = urlsafe_base64_encode(bytes('{}/{}'.format(email,str(verification.token)),'utf-8'))
        url = 'http://{}:{}/api/account/register/{}'.format(
                                                                settings.ALLOWED_HOSTS[0],
                                                                settings.PORT,
                                                                b64)
        
        subject = 'Verify your email to register'
        message = 'Click the link below\n' + url
        emailer([email],subject,message)
        data['response'] = 'Verification mail has been sent to ' + email
    else:
        data = serializer.errors
    return Response(data)

def emailer(recipient,subject,message,email_from = settings.EMAIL_HOST_USER):
    send_mail( subject, message, email_from, recipient )
    return Response('Sent')

@api_view(['GET',])
@permission_classes((IsAuthenticated,))
@authentication_classes((ExpiringTokenAuthentication,))
def logout(request):
    key = request.headers['Authorization'][6:]
    token = ExpiringToken.objects.get(key=key)
    token.expire_time = token.created
    token.save()
    return Response({'logged out.'})

@api_view(['PUT',])
@permission_classes((IsAuthenticated,))
@authentication_classes((ExpiringTokenAuthentication,))
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data)
    user = request.user
    if serializer.is_valid():
        if not user.check_password(serializer.data.get('old')):
            return Response({"Wrong old password."},status=status.HTTP_400_BAD_REQUEST)

        new = serializer.data.get('new')
        new_confirm = serializer.data.get('new_confirm')
        if new != new_confirm:
            return Response({"new passwords not match"},status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new)
        user.save()
        return Response({'successfully changed password'},status=status.HTTP_200_OK)
    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class ObtainExpiringAuthToken(ObtainAuthToken):
    serializer_class = ExpiringAuthTokenSerializer
    if coreapi_schema.is_enabled():
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name="email",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="email",
                        description="Valid email for authentication",
                    ),
                ),
                coreapi.Field(
                    name="password",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Password",
                        description="Valid password for authentication",
                    ),
                ),
            ],
            encoding="application/json",
        )

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return self.serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        now = timezone.now()
        try:
            token = ExpiringToken.objects.select_related('user').get(user=user)
            #return if token not expired
            if token.expire_time > now:
                return Response({'token': token.key})
            else:
                token.key=token.generate_key()
                token.expire_time = now+timedelta(minutes=30)
                token.save()
                return Response({'token': token.key})
        except ExpiringToken.DoesNotExist:
            #create user if not exist
            token = ExpiringToken.objects.create(user=user)
            return Response({'token': token.key})


