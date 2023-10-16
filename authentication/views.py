from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from login_system import settings

from .tokens import generate_token

# Create your views here.
# def home(request):
#     # login_system\templates\authentication\index.html
#     return render(request, "authentication/index.html")

def home(request):
    if request.user.is_authenticated:
        # Assuming "fname" is a property of the user model, replace this with your actual code.
        first_name = request.user.first_name  # Replace with the actual attribute you want to display
    else:
        first_name = None  # Set a default value if the user is not authenticated or "fname" is not available.

    context = {'fname': first_name}
    return render(request, 'authentication/index.html', context)


def signup(request):
    if request.method == "POST":
        # username = request.POST.get('username')
        username = request.POST['username']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('home')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('home')

        if len(username) > 20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('home')

        if password != confirm_password:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('home')

        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('home')

        myuser = User.objects.create_user(username, email, password)
        myuser.first_name = first_name
        myuser.last_name = last_name
        myuser.is_active = False

        myuser.save()

        messages.success(request,"Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
        # Welcome Email
        subject = "Welcome to AGC- Django Login!!"
        message = "Hello " + myuser.first_name + "!! \n" + "Welcome to AGC!! \nThank you for visiting our website.\nWe have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nAnkit Gond"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email  @ AGC - Django Login!!"
        message2 = render_to_string('email_confirmation.html', {

            'name': myuser.first_name, 'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)), 'token': generate_token.make_token(myuser)})
        email = EmailMessage(email_subject, message2, settings.EMAIL_HOST_USER, [myuser.email], )
        email.fail_silently = True
        email.send()

        return redirect('signin')

    return render(request, "authentication/signup.html")


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request, 'activation_failed.html')


def signin(request):
    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['password']

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, "authentication/index.html", {'fname': fname})
        else:
            messages.error(request, "Bad Credentials.")
            return redirect('home')

    return render(request, "authentication/signin.html")


def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!!")
    return redirect('home')
