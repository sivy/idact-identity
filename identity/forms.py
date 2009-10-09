from django import forms
from django.contrib.auth.forms import UserCreationForm
import pytz

from identity.models import Profile
from identity import localflavor


class ProfileForm(forms.ModelForm):

    gender = forms.ChoiceField(choices=(
        ('F', 'Female'),
        ('M', 'Male'),
        ('O', 'Other'),
        ('D', 'Decline to state'),
    ))
    country = forms.ChoiceField(choices=pytz.country_names.items())
    language = forms.ChoiceField(
        choices=sorted(localflavor.LANGUAGE_NAME_FOR_CODE.items(), key=lambda x: x[1]))
    timezone = forms.ChoiceField(choices=((tz, tz) for tz in pytz.common_timezones))

    class Meta:
        model = Profile
        exclude = ('user',)
