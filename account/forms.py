from django import forms
from django.contrib.auth.forms import UserCreationForm
from account.models import Account

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(max_length=30,help_text='email address is required')

    class Meta:
        model = Account
        fields = ('email','password1','password2')