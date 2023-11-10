from django import forms
from .models import Participant, Coordinator, UserProfile, DownloadLog


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
        self.fields.pop('last_login')
        self.fields.pop('edited_by')
        self.fields['date_of_birth'].widget = forms.widgets.DateInput(
            attrs={
                'type': 'date', 'placeholder': 'yyy-mm-dd (DOB) ', 'value':' ',

            }
        )
    class Meta:
        model = Coordinator
        fields = '__all__'


class ParticipantEditForm(forms.ModelForm):
    class Meta:
        model = Participant
        exclude = ['edited_by','is_individual','mobile','aadhar','is_checkedin','participant_type','is_qrassigned','meals','participant_id']  # Include all fields from the Participant model
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
        }

class UserProfileEditForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        exclude = []  # Include all fields from the Participant model
        fields = '__all__'

class SuperuserDownloadForm(forms.ModelForm):
    class Meta:
        model = DownloadLog
        exclude = ['initiator','download_time']
        fields = '__all__'


class CoordinatorEditForm(forms.ModelForm):
    class Meta:
        model = Coordinator
        fields = ['email', 'first_name', 'last_name', 'date_of_birth', 'mobile', 'state', 'college', 'aadhar']
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
        }

class SuperCoordinatorForm(forms.ModelForm):
    class Meta:
        model = Coordinator
        fields = ['email']
class RegistrationForm(forms.ModelForm):
    def __init__(self,*args):
        super().__init__(*args)
        self.fields.pop('edited_by')
        self.fields.pop('is_checkedin')
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
