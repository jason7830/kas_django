from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework import HTTP_HEADER_ENCODING, exceptions
class ExpiringTokenAuthentication(TokenAuthentication):
    def get_model(self):
        if self.model is not None:
            return self.model
        from account.models import ExpiringToken
        return ExpiringToken
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(('User inactive or deleted.'))

        now = timezone.now()
        # This is required for the time comparison
        if token.expire_time < now:
            raise exceptions.AuthenticationFailed('Token has expired')
        #extends the expire time
        token.expire_time = (now+timedelta(minutes=30))
        token.save()

        return (token.user, token)