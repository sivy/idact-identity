from django import forms
from django.contrib.auth.forms import UserCreationForm

from identity.models import Profile


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
