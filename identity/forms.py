from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
import pytz

from identity.models import Profile
from identity import localflavor


class UserForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email')


class MaybeChoiceField(forms.ChoiceField):

    def __init__(self, required=False, choices=None, **kwargs):
        required = False
        choices = list() if choices is None else list(choices)
        choices.insert(0, ('', 'Decline to state'))

        return super(MaybeChoiceField, self).__init__(required=required,
            choices=choices, **kwargs)


class ProfileForm(forms.ModelForm):

    gender = MaybeChoiceField(choices=(
        ('F', 'Female'),
        ('M', 'Male'),
        ('O', 'Other'),
    ))
    country = MaybeChoiceField(choices=pytz.country_names.items())
    language = MaybeChoiceField(choices=sorted(
        localflavor.LANGUAGE_NAME_FOR_CODE.items(), key=lambda x: x[1]))
    timezone = MaybeChoiceField(choices=
        ((tz, tz) for tz in pytz.common_timezones))

    class Meta:
        model = Profile
        exclude = ('user',)
