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

    # def last_login(self):
    #     return None

class Domain(models.Model):
    domain_name = models.CharField(max_length=100)

    def __str__(self):
        return self.domain_name

class Team(models.Model):
    team_head_username = models.CharField(max_length=100)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    team_name = models.CharField(max_length=100,default="SOLO")
    team_size = models.IntegerField(default=1)

    def __str__(self):
        return self.team_name

class Participant(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=15,unique=True)
    state = models.CharField(max_length=100)
    college = models.CharField(max_length=100)
    aadhar = models.CharField(max_length=12,default='',validators=[MinLengthValidator(12)])
    domain_of_interest = models.ForeignKey(Domain, on_delete=models.CASCADE)
    is_individual = models.BooleanField()
    team = models.ForeignKey(Team, on_delete=models.CASCADE, null=True, blank=True)
    edited_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.first_name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_logged_in = models.BooleanField(default=False)
    current_session_id = models.CharField(max_length=32, null=True, blank=True,default=1)

    def __str__(self):
        return self.user.username