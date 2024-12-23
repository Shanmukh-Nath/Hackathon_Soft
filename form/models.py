from django.utils import timezone

from django.db import models
from django.core.validators import MinLengthValidator
from django.contrib.auth.models import AbstractUser, User


class Superuser(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)  # You can use a hashed password here

    def __str__(self):
        return self.username



class Coordinator(models.Model):
    first_name = models.CharField(max_length=100,default='')
    last_name = models.CharField(max_length=100,default='')
    password = models.CharField(max_length=100,default='')
    date_of_birth = models.DateField(default='2023-12-12')
    email = models.EmailField(unique=True,default='')
    mobile = models.IntegerField(max_length=15,blank=True,null=True)
    state = models.CharField(max_length=100,default='')
    college = models.CharField(max_length=100,default='')
    aadhar = models.CharField(max_length=12,default='', validators=[MinLengthValidator(12)])
    is_invited = models.BooleanField(default=False)
    is_setup_complete = models.BooleanField(default=False)
    is_used = models.BooleanField(default=False)
    last_login = models.CharField(default="2023-09-28 04:16:42.041659",max_length=100)
    edited_by = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,blank=True)

    def __str__(self):
        return self.email

    def get_email_field(self):
        return 'email'
    def encoded_id(self):
        import base64
        return base64.b64encode(str(self.id))

    def decode_id(self, id):
        import base64
        return base64.b64decode(id)

    # def last_login(self):
    #     return None

class Domain(models.Model):
    domain_name = models.CharField(max_length=100)

    def __str__(self):
        return self.domain_name


class State(models.Model):
    state_name = models.CharField(max_length=100)

    def __str__(self):
        return self.state_name


class Meals(models.Model):
    meal_name = models.CharField(max_length=100)

    def __str__(self):
        return self.meal_name

class Team(models.Model):
    team_head_username = models.CharField(max_length=100)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    team_name = models.CharField(max_length=100,default="SOLO")
    team_size = models.IntegerField(default=1)
    reg_id = models.CharField(max_length=12,default=0)


    def encode_regid(self):
        import base64
        id_bytes = str(self.reg_id).encode('utf-8')
        return base64.b64encode(id_bytes).decode('utf-8')
    def __str__(self):
        return self.team_name


class DownloadLog(models.Model):
    initiator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='downloads_initiated')
    recipient_name = models.CharField(max_length=200)
    recipient_mobile = models.IntegerField(max_length=10)
    recipient_email = models.EmailField()
    download_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.recipient_name}"



class ParticipantType(models.Model):
    type = models.CharField(max_length=100)

    def __str__(self):
        return self.type


class Gender(models.Model):
    gender = models.CharField(max_length=100,null=True,blank=True)

    def __str__(self):
        return self.gender


class Participant(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    gender = models.ForeignKey(Gender,on_delete=models.CASCADE,null=True,blank=True)
    mobile = models.CharField(max_length=10,unique=True)
    state = models.ForeignKey(State,on_delete=models.CASCADE)
    college = models.CharField(max_length=100)
    aadhar = models.CharField(max_length=12,default='',validators=[MinLengthValidator(12)])
    domain_of_interest = models.ForeignKey(Domain, on_delete=models.CASCADE)
    is_individual = models.BooleanField()
    team = models.ForeignKey(Team, on_delete=models.CASCADE, null=True, blank=True)
    edited_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    is_checkedin = models.BooleanField(default=False)
    registered_date = models.DateField(auto_now_add=True,blank=True,null=True)
    meals = models.ForeignKey(Meals,on_delete=models.CASCADE,blank=True,null=True)
    participant_type = models.ForeignKey(ParticipantType,on_delete=models.CASCADE,blank=True,null=True)
    is_qrassigned = models.BooleanField(default=False)
    participant_id = models.CharField(max_length=12,null=True,blank=True,unique=True)

    def __str__(self):
        return self.first_name

    def encoded_id(self):
        import base64
        id_bytes = str(self.id).encode('utf-8')
        return base64.b64encode(id_bytes).decode('utf-8')

    def decode_id(self,encoded_id):
        import base64
        return base64.b64decode(encoded_id.encode()).decode()

class CheckInOTP(models.Model):
    participant = models.ForeignKey(Participant, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    sent_time = models.DateTimeField(auto_now_add=True)
    usage_time = models.DateTimeField(null=True, blank=True)
    is_expired = models.BooleanField(default=False)

    def __str__(self):
        return f"OTP for {self.participant.first_name}"

class QRCode(models.Model):
    unique_code = models.CharField(max_length=20, unique=True)
    participant = models.ForeignKey(Participant, on_delete=models.CASCADE)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_logged_in = models.BooleanField(default=False)
    current_session_id = models.CharField(max_length=32, null=True, blank=True,default=1)
    last_login = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.username