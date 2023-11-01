import base64
import csv
import datetime
import json
import random

from django.contrib import messages, auth
from django.contrib.auth import login, authenticate, get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, EmailMultiAlternatives, BadHeaderError
from django.db import IntegrityError

from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, int_to_base36
from django import template
from django.views import View
from django.contrib.auth.models import User

from .tokens import complex_token_generator
from .forms import RegistrationForm, SuperuserLoginForm, SuperCoordinatorForm, CoordinatorForm, CoordinatorEditForm, \
    ParticipantEditForm, UserProfileEditForm
from .models import Participant, Team, Domain, Coordinator, UserProfile, CheckInOTP, State, Meals, QRCode





def send_invitations(request):
    coordinators = Coordinator.objects.all()
    for coordinator in coordinators:
        coordinator, created = Coordinator.objects.get_or_create(email=coordinator.email)
        if not coordinator.is_invited:
            # Generate a unique token for each coordinator
            uid = urlsafe_base64_encode(force_bytes(coordinator.pk))
            token = complex_token_generator.make_token(coordinator)

            # Build the account setup link
            current_site = get_current_site(request)
            setup_url = f"http://{current_site.domain}/setup/{uid}/{token}/"

            # Send the email invitation
            send_mail(
                "Coordinator Account Setup",
                f"Hi {coordinator.first_name},\n\n"
                f"Please set up your coordinator account by clicking the following link:\n\n"
                f"{setup_url}\n\n"
                f"Thank you!",
                "hack@example.com",
                [coordinator.email],
            )

            # Mark the coordinator as invited
            coordinator.is_invited = True
            coordinator.save()

    return redirect('superuser_dashboard')  # Redirect to a success page



def setup_coordinator_account(request):
    uid = request.GET.get('uid')
    if uid is not None:
        coordinator = Coordinator.objects.get(pk=uid)
        if request.method == 'POST':
            form = CoordinatorForm(request.POST)
            if form.is_valid():
                email = coordinator.email
                username = request.POST['username']
                first_name = request.POST['first_name']
                last_name = request.POST['last_name']
                password = request.POST['password']
                date_of_birth = request.POST['date_of_birth']
                mobile = request.POST['mobile']
                state = request.POST['state']
                college = request.POST['college']
                aadhar = request.POST['aadhar']
                hash = make_password(password)

                # Create a User object for authentication
                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.last_name = last_name
                user.save()

                # Update the Coordinator object with additional details
                coordinator.first_name = first_name
                coordinator.date_of_birth = date_of_birth
                coordinator.mobile = mobile
                coordinator.state = state
                coordinator.college = college
                coordinator.aadhar = aadhar
                coordinator.is_setup_complete = True
                coordinator.is_used = True
                coordinator.save()

                return redirect('coordinator_login')
        else:
            form = CoordinatorForm()
            em = coordinator.email
            return render(request, 'coordinator/setup_coordinator_account.html', {'form': form, 'email': em})
# views.py

def link_coordinator_validation(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64)
        coordinator = Coordinator.objects.get(pk=uid)
        u = int(uid)

        is_valid_token = complex_token_generator.check_token(coordinator, token)

        if is_valid_token and coordinator.is_used == False:
            redirect_url = reverse('setup_coordinator_account') + f'?uid={u}'
            return HttpResponseRedirect(redirect_url)
        else:
            return redirect("invalid_activation_link")

    except (TypeError, ValueError, OverflowError, Coordinator.DoesNotExist):
        print("Error")
    return redirect('invalid_activation_link')



def coordinator_login(request):
    if request.user.is_authenticated:
        if request.user.is_active:
            return redirect('coordinator_dashboard')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = auth.authenticate(request, username=username, password=password)
            if user is not None:
                user.session_key = request.session.session_key
                user.save()
                auth.login(request, user)
                if user is not None and user.is_active:
                    user.session_key = request.session.session_key
                    user.save()
                    auth.login(request, user)
                    user_profile = UserProfile.objects.get_or_create(user_id=request.user.id)
                    if user_profile[0].is_logged_in:
                        messages.error(request, "You are already logged in.")
                        auth.logout(request)
                        return redirect('coordinator_login')
                    else:
                        user_profile[0].is_logged_in = True
                        user_profile[0].current_session_id = request.session.session_key
                        user_profile[0].last_login = timezone.now()
                        user_profile[0].save()
                        return redirect('coordinator_dashboard')
            else:
                print("invalid")
                messages.error(request, 'Invalid credentials.')

    return render(request, 'coordinator/coordinator_login.html')


@login_required(login_url='/superuser/login/')
def view_coordinators(request):
    coordinators = Coordinator.objects.all()
    return render(request, 'superuser/coordinators_list.html', {'coordinators': coordinators})


@login_required(login_url='/superuser/login/')
def view_participants_super(request):
    coordinators = Participant.objects.all()
    return render(request, 'superuser/participants_list.html', {'coordinators': coordinators})


@login_required(login_url='/superuser/login/')
def edit_participant_super(request, participant_id):
    participant = Participant.objects.get(pk=participant_id)

    if request.method == 'POST':
        form = ParticipantEditForm(request.POST, instance=participant)
        if form.is_valid():
            participant.edited_by = request.user
            form.save()
            return redirect('view_participants_super')
    else:
        form = ParticipantEditForm(instance=participant)

    return render(request, 'superuser/edit_participant.html', {'form': form})


@login_required(login_url='/coordinator/login/')
def edit_participant_coordinator(request, encoded_id):
    participant_id = int(base64.b64decode(encoded_id.encode()).decode())
    participant = Participant.objects.get(pk=participant_id)
    if request.method == 'POST':
        form = ParticipantEditForm(request.POST, instance=participant)
        if form.is_valid():
            participant.edited_by = request.user
            form.save()
            return redirect('view_participants_coordinator')
    else:
        form = ParticipantEditForm(instance=participant)

    return render(request, 'coordinator/edit_participant.html', {'form': form,'p':participant})


@login_required(login_url='/coordinator/login')
def view_participants_coordinator(request):
    coordinators = Participant.objects.all()
    teams = Team.objects.all()
    return render(request, 'coordinator/participants_list.html', {'coordinators': coordinators,'teams':teams})


@login_required(login_url='/coordinator/login/')
def coordinator_dashboard(request):
    if request.user.is_active:
        cur = request.session.session_key
        user_profile = UserProfile.objects.get(user_id=request.user.id)
        if not user_profile.current_session_id == cur:
            print("here")
            auth.logout(request)
            messages.error(request, "you are already logged in.")
            return redirect('coordinator_login')
        else:
            coordinators = Participant.objects.all()
            user = request.user.username
            l = len(coordinators)
            return render(request, "coordinator/coordinator_dashboard.html", {"length": l,'user':user})


@login_required(login_url='/superuser/login/')
def edit_coordinator(request, coordinator_id):
    coordinator = Coordinator.objects.get(pk=coordinator_id)

    if request.method == 'POST':
        form = CoordinatorEditForm(request.POST, instance=coordinator)
        if form.is_valid():
            coordinator.edited_by = request.user
            form.save()
            return redirect('superuser_dashboard')
    else:
        form = CoordinatorEditForm(instance=coordinator)

    return render(request, 'superuser/edit_coordinator.html', {'form': form, 'coordinator': coordinator})


@login_required(login_url='/superuser/login/')
def edit_coordinator_session(request, coordinator_id):
    user = User.objects.get(id=coordinator_id)
    coordinator = UserProfile.objects.get(user_id=user.id)

    if request.method == 'POST':
        form = UserProfileEditForm(request.POST, instance=coordinator)
        if form.is_valid():
            form.save()
            return redirect('superuser_dashboard')
    else:
        form = UserProfileEditForm(instance=coordinator)

    return render(request, 'superuser/edit_coordinator_session.html', {'form': form, 'coordinator': coordinator})



def super_coordinator_session(request):
    c = UserProfile.objects.all()
    return render(request,'superuser/coordinator_session.html',{'coords':c})

def logout(request):
    if request.user.is_superuser:
        request.session.flush()
        return redirect('superuser_login')
    else:
        user_profile = UserProfile.objects.get(user_id=request.user.id)
        user_profile.is_logged_in = False
        user_profile.current_session_id = False
        user_profile.save()
        request.session.flush()
        return redirect('coordinator_login')


def invalid_activation_link(request):
    return render(request, 'coordinator/invalid_token.html')


def force_text(param):
    pass


def superuser_login(request):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect('superuser_dashboard')
        else:
            messages.error(request, "You are not authorized.")
            return redirect('coordinator_login')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = auth.authenticate(request, username=username, password=password)
            if user is not None and user.is_superuser:
                user.session_key = request.session.session_key
                user.save()
                auth.login(request, user)
                return redirect('superuser_dashboard')
            else:
                messages.error(request, 'Invalid credentials. Please try again.')

    return render(request, 'superuser/superuser_login.html')


'''class SessionTimeoutMiddleware:
    print("Here")
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Check if the user is authenticated and has a UserProfile
        if request.user.is_authenticated:
            try:
                print("Here")
                user_profile = UserProfile.objects.get(user=request.user)

                # Check if the session has expired (e.g., after 30 minutes)
                session_timeout = 2600  # 30 minutes in seconds
                last_login = user_profile.last_login
                current_time = timezone.now()
                if last_login and (current_time - last_login).total_seconds() > session_timeout:
                    print((current_time-last_login).total_seconds())
                    user_profile.is_logged_in = False
                    user_profile.current_session_id = None
                    user_profile.save()
                    auth.logout(request)
            except UserProfile.DoesNotExist:
                pass  # UserProfile not found, no need to check session timeout

        return response
'''



@login_required(login_url='/superuser/login/')
def send_invite(request):
    coordinators = Coordinator.objects.all()
    cd = []
    for c in coordinators:
        if c.is_invited == False:
            cd.append(c.email)
    return render(request, 'superuser/send_invite.html', {'emails': cd})


@login_required(login_url='/superuser/login/')
def superuser_dashboard(request):
    if request.user.is_superuser:
            p = len(Participant.objects.all())
            user = request.user.username
            l = len(Coordinator.objects.all())
            return render(request, "superuser/superuser_dashboard.html", {"length": l,"participant":p,"user":user})
    else:
        return redirect('coordinator_login')


@login_required(login_url='/superuser/login/')
def delete_coordinator_super(request, coordinator_id):
    coor = Coordinator.objects.get(pk=coordinator_id)
    email = coor.email
    if coor.is_setup_complete:
        user = User.objects.get(email=email)
        user.delete()
    coor.delete()
    messages.warning(request, f"User '{email}' has been deleted successfully.")
    return redirect('superuser_dashboard')


@login_required(login_url='/superuser/login/')
def add_coordinator(request):
    print(request)
    if request.method == "POST":
        form = SuperCoordinatorForm(request.POST)
        if form.is_valid():
            print(request.POST)
            # Save the coordinator
            form.save()
            return redirect("superuser_dashboard")
    else:
        form = SuperCoordinatorForm()
    return render(request, "superuser/add_coordinator.html", {"form": form})



@login_required(login_url='/coordinator/login/')
def part_check_in(request):
    coordinator = Participant.objects.filter(is_checkedin=False)
    return render(request,'coordinator/checkin_list.html',{'coordinators':coordinator})

@login_required(login_url='/coordinator/login/')
def part_check_in_success(request):
    coordinator = Participant.objects.filter(is_checkedin=True)
    return render(request,'coordinator/success_check_in.html',{'coordinators':coordinator})


@login_required(login_url='/coordinator/login/')
def part_qr_success(request):
    coordinator = QRCode.objects.all()
    return render(request,'coordinator/qr_check.html',{'coordinators':coordinator})


@login_required(login_url='/coordinator/login/')
def part_qr_list(request):
    coordinator = Participant.objects.filter(is_qrassigned=False)
    return render(request,'coordinator/qr_assign.html',{'coordinators':coordinator})


@login_required(login_url='/coordinator/login/')
def part_qr_check(request):
    coordinator = Participant.objects.filter(is_qrassigned=True)
    return render(request,'coordinator/qr_check.html',{'coordinators':coordinator})

@login_required(login_url='/coordinator/login/')
def qr_scan(request,encoded_id):
    global participant
    try:
        participant_id = int(base64.b64decode(encoded_id.encode()).decode())
        participant = Participant.objects.get(id=participant_id)

        if request.method == 'POST':
            print(request.POST)
            qr_code = request.POST.get('qrcode')
            print(qr_code)

            if not qr_code:
                messages.error(request, "QR Code is required.")
            else:
                # Check if the QR code is valid or exists in your system
                # You should implement the logic to verify and assign the QR code to the participant
                if 1==1:
                    qr = QRCode.objects.create(unique_code=qr_code,participant_id=participant.id)
                    qr.save()
                    participant.is_qrassigned = True
                    participant.save()

                    messages.success(request, "QR code assigned successfully.")
                    return redirect('coordinator_dashboard')
                else:
                    messages.error(request, "Invalid QR Code.")

    except Participant.DoesNotExist:
        messages.error(request, "Participant not found.")

    return render(request, 'coordinator/qr_scan_part.html', {'part': participant})

@login_required(login_url='/coordinator/login/')
def is_valid_qr_code(request,qrcode):
        return True


def generate_otp(participant):
    try:
        # Try to retrieve an existing OTP for the participant
        checkin_otp = CheckInOTP.objects.get(participant=participant)

        # Check if the OTP is expired
        if (timezone.now() - checkin_otp.sent_time).total_seconds() >= 300:
            # OTP has expired, generate a new one
            otp = ''.join(random.choice('0123456789') for _ in range(6))
            checkin_otp.otp = otp
            checkin_otp.is_expired = False
            checkin_otp.sent_time = timezone.now()
            checkin_otp.save()
        else:
            # OTP is not expired, send the same OTP again
            otp = checkin_otp.otp
    except CheckInOTP.DoesNotExist:
        # Generate a new OTP if it doesn't exist for the participant
        otp = ''.join(random.choice('0123456789') for _ in range(6))
        checkin_otp = CheckInOTP.objects.create(participant=participant, otp=otp)

    # Send the OTP to the participant's email (implement this part using email sending libraries)
    subject = "CheckIN OTP"
    message = "Please Use this OTP for Checking in to event with your nearest Coordinator " + otp
    from_email = "123@example.com"
    recepient = [participant.email]
    send_mail(subject,message,from_email,recepient)

    return otp


@login_required(login_url='/coordinator/login/')
def verify_otp(request, encoded_id):
    if request.method == 'POST':
        print(request.POST)
        otp_entered = request.POST.get('combined_otp')
        print(otp_entered)
        participant_id = int(base64.b64decode(encoded_id.encode()).decode())
        participant = Participant.objects.get(id=participant_id)

        try:
            # Try to retrieve an existing OTP for the participant
            checkin_otp = CheckInOTP.objects.get(participant=participant)

            # Check if the OTP is within the allowed time frame (e.g., 5 minutes)
            if (timezone.now() - checkin_otp.sent_time).total_seconds() <= 300 and otp_entered == checkin_otp.otp:
                checkin_otp.usage_time = timezone.now()
                checkin_otp.is_expired = True
                checkin_otp.save()
                participant.is_checkedin = True
                participant.save()

                # Mark the participant as checked in or perform any other required actions
                # ...
                messages.success(request, "Participant Checked In")
                return redirect('coordinator_dashboard')
            elif (timezone.now() - checkin_otp.sent_time).total_seconds() >= 300:
                # OTP has expired, generate a new one and send again
                otp = generate_otp(participant)
                messages.error(request, "OTP Expired. New OTP Sent.")
            elif otp_entered!=checkin_otp and otp_entered != '' and otp_entered is not None:
                messages.error(request,"Invalid OTP")
        except CheckInOTP.DoesNotExist:
            messages.error(request, "Invalid OTP")

    participant_id = int(base64.b64decode(encoded_id.encode()).decode())
    participant = Participant.objects.get(pk=participant_id)
    checked = CheckInOTP.objects.filter(participant_id = participant_id).exists()
    if checked:
        chk = CheckInOTP.objects.get(participant_id = participant_id)
        if chk.usage_time is not None:
            messages.error(request,"Participant already checkedin")
            return redirect('coordinator_dashboard')
    otp = generate_otp(participant)
    messages.success(request, "OTP Successfully Sent")

    return render(request, 'coordinator/checkin_otp_verification.html', {'participant': participant, 'otp': otp})






def registration(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            participant = form.save(commit=False)
            is_individual = request.POST.get('is_individual')
            if is_individual == '1':
                participant.is_individual = True
                participant.save()
                # Create a team for the individual participant
                team = Team.objects.create(
                    team_head_username=participant.first_name,
                    domain=Domain.objects.get(pk=participant.domain_of_interest.id)
                )
                participant.team = team
                participant.save()
                send_reg_success(request,participant)
                return redirect('success')
            else:
                participant.is_individual = False

                print(request.POST)
                team_size = int(request.POST.get('team_size'))
                team_name = request.POST.get('team_name')
                if 3 <= team_size <= 5:

                    team = Team.objects.create(
                        team_head_username=participant.first_name,
                        domain=Domain.objects.get(pk=participant.domain_of_interest.id)

                    )
                    team.team_name = team_name
                    team.team_size = team_size
                    team.save()
                    participant.team = team
                    participant.save()

                    teams_email = []
                    teams_mobile = []
                    teams_aadhar = []

                    for i in range(team_size - 1):
                        teams_email.append(request.POST.get(f'team_member_email_{i}'))
                        teams_mobile.append(request.POST.get(f'team_member_mobile_{i}'))
                        teams_aadhar.append(request.POST.get(f'team_member_aadhar_{i}'))
                        if participant.email==request.POST.get(f'team_member_email_{i}') or participant.mobile==request.POST.get(f'team_member_mobile_{i}') or participant.aadhar==request.POST.get(f'team_member_aadhar_{i}'):
                            participant.delete()
                            team.delete()
                            messages.error(request,'You cannot use same details')
                            return redirect('registration')
                        else:
                            # print(request.POST.get(f'team_member_state_{i}'))
                            state = State.objects.get(state_name=request.POST.get(f'team_member_state_{i}'))
                            meal = Meals.objects.get(meal_name=request.POST.get(f'team_member_meals_{i}'))
                            team_member = Participant(
                                first_name=request.POST.get(f'team_member_first_name_{i}'),
                                last_name=request.POST.get(f'team_member_last_name_{i}'),
                                date_of_birth=request.POST.get(f'team_member_date_of_birth_{i}'),
                                email=request.POST.get(f'team_member_email_{i}'),
                                mobile=request.POST.get(f'team_member_mobile_{i}'),
                                state=state.id,
                                college=request.POST.get(f'team_member_college_{i}'),
                                aadhar=request.POST.get(f'team_member_aadhar_{i}'),
                                domain_of_interest=participant.domain_of_interest,
                                meals = meal.id,
                                is_individual=False,
                                team=team
                            )
                            team_member.save()

                    if set(teams_email) != team_size or set(teams_mobile) != team_size or set(teams_aadhar) != team_size:
                        participant.delete()
                        team.delete()
                        messages.error(request,"You cannot use same details in form, please check the data of these unique fields - Email, Mobile, Aadhar.")
                        return redirect('coordinator_login')
                    send_reg_success(request,participant)
                    return redirect('success')

    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})



def send_reg_success(request,participant):
    parts = Participant.objects.filter(team_id=participant.team_id)
    print(parts)
    for p in parts:
        subject = "Successfully Registered"
        plaintext = template.loader.get_template('Emails/reg-success.html')
        htmltemp = template.loader.get_template('Emails/reg-success.html')
        domain = get_current_site(request).domain
        from_email = "noreply@exam.in"
        c = {
            'username':p.first_name + " " + p.last_name,
            'domain':p.domain_of_interest.domain_name,
            'teamname':p.team.team_name,
            'teamsize':p.team.team_size,
        }
        text_content = plaintext.render(c)
        html_content = htmltemp.render(c)
        try:
            msg = EmailMultiAlternatives(subject, text_content, from_email, [p.email])
            msg.attach_alternative(html_content, 'text/html')
            msg.send()
        except BadHeaderError:
            return HttpResponse('Invalid header found.')


class EmailValidation(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']

        if Participant.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'Email is already registered'}, status=409)

        return JsonResponse({'email_valid': True})

class MobileValidation(View):
    def post(self, request):
        data = json.loads(request.body)
        mobile = data['mobile']

        if Participant.objects.filter(mobile=mobile).exists():
            return JsonResponse({'mobile_error': 'Mobile is already registered'}, status=409)

        return JsonResponse({'mobile_valid': True})  # Modify this as per your validation logic

class TeamNameValidation(View):
    def post(self, request):
        data = json.loads(request.body)
        team_name = data['team_name']


        if Team.objects.filter(team_name=team_name).exists():
            return JsonResponse({'team_name_error': 'Team Name already taken'}, status=400)

        return JsonResponse({'team_name_valid': True})

class CoordinatorMobileValidation(View):
    def post(self, request):
        data = json.loads(request.body)
        mobile = data['mobile']

        if Coordinator.objects.filter(mobile=mobile).exists():
                return JsonResponse({'mobile_error': 'Mobile is already registered'}, status=409)

        return JsonResponse({'mobile_valid': True})  # Modify this as per your validation logic

class CoordinatorUsernameValidation(View):
    def post(self, request):
        print("here")
        data = json.loads(request.body)
        mobile = data['username']

        if User.objects.filter(username=mobile).exists():
                return JsonResponse({'username_error': 'Username is already registered'}, status=409)

        return JsonResponse({'username_valid': True})  # Modify this as per your validation logic

class CoordinatorAadharValidation(View):
    def post(self, request):
        data = json.loads(request.body)
        mobile = data['aadhar']

        if Coordinator.objects.filter(aadhar=mobile).exists():
                return JsonResponse({'aadhar_error': 'Aadhar Number is already registered'}, status=409)

        return JsonResponse({'aadhar_valid': True})


class SuperUserEmailValidation(View):
    def post(self, request):
        data = json.loads(request.body)
        mobile = data['email']

        if Coordinator.objects.filter(email=mobile).exists():
                return JsonResponse({'email_error': 'Email is already registered'}, status=409)

        return JsonResponse({'email_valid': True})


def success(request):
    print(request.POST)
    return render(request, 'success.html')

def index(request):
    return render(request,'index.html')
