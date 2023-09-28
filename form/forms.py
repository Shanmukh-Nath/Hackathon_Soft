from django import forms
from .models import Participant,Coordinator



class SuperuserLoginForm(forms.Form):
    username = forms.CharField(max_length=100)
    password = forms.CharField(max_length=100, widget=forms.PasswordInput)


class CoordinatorForm(forms.ModelForm):
    def __init__(self,*args):
        super().__init__(*args)
        self.fields.pop('is_invited')
        self.fields.pop('is_setup_complete')
        self.fields.pop('email')
        self.fields.pop('is_used')
        self.fields['date_of_birth'].widget = forms.widgets.DateInput(
            attrs={
                'type': 'date', 'placeholder': 'yyy-mm-dd (DOB) ', 'value':' ',

            }
        )
    class Meta:
        model = Coordinator
        fields = '__all__'

class SuperCoordinatorForm(forms.ModelForm):
    class Meta:
        model = Coordinator
        fields = ['email']
class RegistrationForm(forms.ModelForm):
    def __init__(self,*args):
        super().__init__(*args)
        self.fields['date_of_birth'].widget = forms.widgets.DateInput(
            attrs={
                'type':'date','placeholder':'yyy-mm-dd (DOB) ',

            }
        )
        self.fields.pop('is_individual')
        self.fields.pop('team')
    class Meta:
        model = Participant
        fields = '__all__'
