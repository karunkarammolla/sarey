from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.models import User,auth
from django.core.exceptions import ObjectDoesNotExist, ValidationError

from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import  Registred,LoginForm
from django.views.generic import *
from django import forms
from django.core.mail import send_mail
from django.template import loader
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.conf import settings
from django.core.validators import validate_email



#account login
def logint(request):
    if request.method == 'POST':
        try:
            user = LoginForm.objects.get(mail=request.POST['email'], password=request.POST['password'])
            print('user',user)
            request.session['username']=user.user
            request.session['email']=user.mail
            request.session['id']=user.id
            return redirect('home')
            # return HttpResponse('main page')
        except LoginForm.DoesNotExist as e:
            return HttpResponse('Please Enter valid credentials')
    return render(request,'login.html')



def outerFunction(originalFunction):
    def logins(request):
        if request.session.get('username'):
            return originalFunction(request)
        else:

            return redirect('logint')

    return logins

@outerFunction
def home(request):
    return render(request, 'home.html', {})


@outerFunction
def about(request):
    return render(request, 'mainpage//about.html', {})

@outerFunction
def services(request):
        return render(request, 'mainpage//services.html', {})


@outerFunction
def learn_more(request):
    return render(request, 'mainpage//learn_more.html', {})


@outerFunction
def registred_members(request):
    regist = Registred.objects.all()
    return render(request, 'registred//index.html', {'registrednumbers':regist})


@outerFunction
def logout(request):
    auth.logout(request)
    return redirect('/')


#admin
def admin_login(request):

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request,user)
            request.session['user'] = 1
            return redirect('edit')
            # return render(request, 'home.html')
        else:
            messages.info(request,'invalid credentials')
            return render(request, 'admin_login.html')
    else:
        return render(request,'admin_login.html')


def outerFunctiond(originalFunctiond):
    def logins(request):
        if request.session.get('user'):
            return originalFunctiond(request)
        else:

            return redirect('admin_login')

    return logins

@outerFunctiond
def edit_page(request):
    if request.method == 'GET':
        return render(request, 'admin/editpage.html', {})
    elif request.method == 'POST':
        year = request.POST['year']
        id = request.POST['id']
        name = request.POST['name']
        membership = request.POST['membership']
        Registred(Year=year,Name=name,ID=id,Membership=membership).save()
        messages.add_message(request, messages.INFO, 'Data inserted Successfully')
        return redirect('edit')

@outerFunctiond
def adminlogout(request):
    auth.logout(request)
    return redirect('admino')


@outerFunctiond
def registred_members1(request):
    regist = Registred.objects.all()
    return render(request, 'registred//admin_index.html', {'registrednumbers':regist})
@outerFunctiond
def delete_record(request,id):
    obj= Registred.objects.get(id=id)
    obj.delete()

    return redirect('registred1')

@outerFunctiond
def insert_tab(request):
    return redirect('edit')
@outerFunctiond
def update_record(request,id):
    obj= Registred.objects.get(id=id)
    if request.method == 'GET':
        return render(request,'admin\\update.html',{'update':obj})
    elif request.method == 'POST':
        obj.Year= request.POST['year']
        obj.ID=request.POST['id']
        obj.Name=request.POST['name']
        obj.Membership=request.POST['membership']
        obj.save()
        return redirect('registred1')
    return redirect('registred1')


#manage accounts
@outerFunctiond
def login_form(request):
    if request.method == 'POST':
        Username = request.POST['Username']
        Password = request.POST['Password']
        Email=     request.POST['Email']
        Phone =    request.POST['Phone']
        LoginForm(user = Username,
                  password= Password,
                  mail=Email,
                  phone =Phone).save()
        return redirect('edit')

@outerFunctiond
def signup(request):
    return render(request, 'Signup//signup.html', {})



#AJAY
class PasswordRequestForm(forms.Form):
    email = forms.CharField(label='email', max_length=254)

class PasswordResetForm(forms.Form):
    new_password = forms.CharField(label='new_password', max_length=254)

class UserReset(FormView):
    form_class = PasswordResetForm

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        new_password = form.data['new_password']
        id = kwargs['id']
        users = LoginForm.objects.filter(id=id)
        if users.exists():
            user = users.first()
            user.password = new_password
            user.save()
        return HttpResponse('Password Updated')
class UserForgot(FormView):
    form_class = PasswordRequestForm

    @staticmethod
    def validate_email(email):
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if not form.is_valid():
            return HttpResponse('Invalid data')
        email = form.data['email']
        if not self.validate_email(email):
            return HttpResponse('Not a valid email')

        users = LoginForm.objects.filter(mail=email)
        if users.exists():
            user = users.first()
            c = {
                'email': user.mail,
                'domain': request.META['HTTP_HOST'],
                'site_name': 'your site',
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'user': user,
                'protocol': 'http',
                'url':'{}/user_reset/{}'.format(settings.HOST, user.pk)
            }
            subject_template_name = 'Reset your email password'
            email_template_name = 'get_password.html'
            # subject = loader.render_to_string(subject_template_name, c)
            subject = 'Reset your email password'
            email = loader.render_to_string(email_template_name, c)
            send_mail(subject, email, 'karunakarammolla@gmail.com', [user.mail], fail_silently=False)
            # result = self.form_valid(form)
            return HttpResponse('Email sent')
        else: return HttpResponse('User does not exists')