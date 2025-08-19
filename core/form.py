from django import forms
from .models import *
from datetime import date
from django.core import validators
from django.contrib.auth.forms import SetPasswordForm
from django.core.exceptions import ValidationError
from django.db.models import Sum


class SynergyApplicationForm(forms.ModelForm):
    class Meta:
        model = SynergyApplication
        fields = ['full_name', 'email', 'phone', 'pitch', 'cv']


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        label='',
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'}),
    )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError(
                "This email is not associated with any account.",
                code="invalid"
            )
        return email

class PasswordResetForm(SetPasswordForm):
    new_password1 = forms.CharField(
        label='',
        widget=forms.PasswordInput(attrs={'class': 'form-control m-2', 'placeholder': 'Enter new password'}),
    )    
    new_password2 = forms.CharField(
        label='',
        widget=forms.PasswordInput(attrs={'class': 'form-control m-2', 'placeholder': 'Confirm new password'}),
    )

    class Meta:
        model = User
        fields = ('new_password1', 'new_password2')

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match.")
        return password2
