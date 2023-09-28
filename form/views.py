import csv
import datetime

from django.contrib import messages
from django.contrib.auth import login, authenticate, get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password,check_password
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, int_to_base36
from django.views import View
from django.contrib.auth.models import User

from .tokens import complex_token_generator
from .forms import RegistrationForm, SuperuserLoginForm,SuperCoordinatorForm,CoordinatorForm
from .models import Participant, Team, Domain,Coordinator


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

    return redirect('superuser_dashboard') # Redirect to a success page

# views.py

def setup_coordinator_account(request,uidb64,token):
    try:
        uid = urlsafe_base64_decode(uidb64)
        coordinator = Coordinator.objects.get(pk=uid)

        is_valid_token = complex_token_generator.check_token(coordinator,token)

        if is_valid_token and coordinator.is_used == False:
            if request.method == 'POST':
                form = CoordinatorForm(request.POST)
                if form.is_valid():
                    email = coordinator.email
                    username= request.POST['username']
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
                    #coordinator.is_used = True
                    coordinator.save()

                    return redirect('coordinator_login')
            else:
                form = CoordinatorForm()
                em = coordinator.email
                return render(request,'coordinator/setup_coordinator_account.html',{'form':form,'email':em})
    except (TypeError, ValueError, OverflowError, Coordinator.DoesNotExist):
                print("Error")
    return redirect("invalid_activation_link")



def coordinator_login(request):
    #send_invitations(request)
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(f"Username: {username}")
        print(f"Password: {password}")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('coordinator_dashboard')
        else:
            print("invalid")
            messages.error(request, 'Invalid credentials. Please try again.')

    return render(request, 'coordinator/coordinator_login.html')

@login_required(login_url='/superuser/login/')
def view_coordinators(request):
    coordinators = Coordinator.objects.all()
    return render(request,'superuser/coordinators_list.html',{'coordinators':coordinators})




def view_participants(request):
    pass
@login_required(login_url='/coordinator/login/')
def coordinator_dashboard(request):
    coordinators = Participant.objects.all()
    l = len(coordinators)
    return render(request, "coordinator/coordinator_dashboard.html", {"length": l})

@login_required(login_url='/superuser/login/')
def edit_coordinator(request,id):
    return None


def logout(request):
    print(request.user)
    request.session.flush()
    return redirect('registration')


def invalid_activation_link(request):
    return render(request,'coordinator/invalid_token.html')
def force_text(param):
    pass



def superuser_login(request):
    #send_invitations(request)
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(f"Username: {username}")
        print(f"Password: {password}")
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_superuser:
            login(request, user)
            return redirect('superuser_dashboard')
        else:
            messages.error(request, 'Invalid credentials. Please try again.')

    return render(request, 'superuser/superuser_login.html')

@login_required(login_url='/superuser/login/')
def send_invite(request):
    coordinators = Coordinator.objects.all()
    cd = []
    for c in coordinators:
        if c.is_invited == False:
            cd.append(c.email)
    return render(request,'superuser/send_invite.html',{'emails':cd})

@login_required(login_url='/superuser/login/')
def superuser_dashboard(request):
    coordinators = Coordinator.objects.all()
    l = len(coordinators)
    return render(request, "superuser/superuser_dashboard.html", {"length": l})

@login_required(login_url='/superuser/login/')
def add_coordinator(request):
    if request.method == "POST":
        form = SuperCoordinatorForm(request.POST)
        if form.is_valid():
            # Save the coordinator
            form.save()
            return redirect("superuser_dashboard")
    else:
        form = SuperCoordinatorForm()
    return render(request, "superuser/add_coordinator.html", {"form": form})




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
                return redirect('success')
            else:
                participant.is_individual = False

                print(request.POST)
                team_size = int(request.POST.get('team_size'))
                team_name = request.POST.get('team_name')
                print(team_name)
                if 3 <= team_size <= 5:

                    team = Team.objects.create(
                        team_head_username=participant.first_name,
                        domain=Domain.objects.get(pk=participant.domain_of_interest.id)

                    )
                    team.team_name = team_name
                    team.save()
                    participant.team = team
                    participant.save()

                    for i in range(team_size - 1):
                        team_member = Participant(
                            first_name=request.POST.get(f'team_member_first_name_{i}'),
                            last_name=request.POST.get(f'team_member_last_name_{i}'),
                            date_of_birth=request.POST.get(f'team_member_date_of_birth_{i}'),
                            email=request.POST.get(f'team_member_email_{i}'),
                            mobile=request.POST.get(f'team_member_mobile_{i}'),
                            state=request.POST.get(f'team_member_state_{i}'),
                            college=request.POST.get(f'team_member_college_{i}'),
                            aadhar=request.POST.get(f'team_member_aadhar_{i}'),
                            domain_of_interest=participant.domain_of_interest,
                            is_individual=False,
                            team=team
                        )
                        team_member.save()
                    return redirect('success')
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})

def success(request):
    return render(request, 'reg.html')
