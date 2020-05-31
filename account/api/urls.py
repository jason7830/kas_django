from django.urls import path
from account.api.views import (
                                registration_view, 
                                ObtainExpiringAuthToken, 
                                logout, 
                                change_password,
                                apply_registration,
                               )
from rest_framework.authtoken.views import obtain_auth_token
app_name = 'account'

urlpatterns = [
        path('register/<b64info>',registration_view,name='register'),
        #takes username(email) and password fields
        path('login',ObtainExpiringAuthToken.as_view(),name='login'),
        path('logout',logout,name='logout'),
        path('change_pw',change_password,name='change_pw'),
        path('apply_registration',apply_registration,name='apply_registration'),
]