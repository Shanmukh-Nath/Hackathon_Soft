## Hackathon Software
### Implemented Background Emails Sending
This is achieved using `django_background_tasks` package.
Setup of Django Background Tasks

1. Install `django_background_tasks`
```
pip install django-background-tasks
```
**Note:** The package is not Supported by Django 4.x

2. Add it to your installed apps in `settings.py`:
```
INSTALLED_APPS = (
    # ... other installed apps
    'background_task',
)
```

3. Migrate your database to create the necessary tables:

```
python manage.py migrate background_task
```

4. Define a background task for sending emails in your `views.py`:
```
from background_task import background

@background(schedule=1)
def send_email_task(email_subject, text_content, from_email, email,html_content):
    msg = EmailMultiAlternatives(email_subject, text_content, from_email, [email])
    msg.attach_alternative(html_content, 'text/html')
    msg.send()
```

5. Modify your `send_reg_success` function to use the background task:
```
def send_reg_success(request, participant):
    parts = Participant.objects.filter(team_id=participant.team_id)
    for p in parts:
        subject = "Successfully Registered"
        # ... Your email content logic here

        # Call your task instead of sending the email directly
        send_email_task(subject,text_content,from_email,p.email,html_content)
```

6. **Run the process** that executes the tasks:
```
python manage.py process_tasks
```
**Note:** Step 6 is very Important, if the task processing is not started the emails will be stored in the queue.
