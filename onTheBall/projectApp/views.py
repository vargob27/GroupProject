from django.shortcuts import render, redirect
from django.contrib import messages, admin
from .models import *
from datetime import datetime
import bcrypt

def index(request):
    if 'user_id' in request.session:
        return redirect('/home')
    return render(request, 'login.html')

def success(request):
    if 'user_id' not in request.session:
        return redirect('/')
    this_user = User.objects.filter(id=request.session['user_id'])
    context = {
        'user': this_user[0],
    }
    return render(request, 'home.html', context)

def register(request):
    if request.method == 'POST':
        errors = User.objects.registration_validator(request.POST)
        if len(errors) != 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
    # hash password
        hashed_pw = bcrypt.hashpw(
            request.POST['password'].encode(), bcrypt.gensalt()).decode()
    # create User
        new_user = User.objects.create(
            first_name=request.POST['first_name'], last_name=request.POST[
                'last_name'], email=request.POST['email'], password=hashed_pw
        )
    # create session
        request.session['user_id'] = new_user.id
        return redirect('/home')
    return redirect('/')

def login(request):
    if request.method == "POST":
        errors = User.objects.login_validator(request.POST)
        if len(errors) != 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        this_user = User.objects.filter(email=request.POST['email'])
        request.session['user_id'] = this_user[0].id
        return redirect('/home')
    return redirect('/')

def logout(request):
    request.session.flush()
    return redirect('/')

def post(request):
    if 'user_id' not in request.session:
        return redirect('/')
    Comment_Thread.objects.create(message=request.POST['message'], poster=User.objects.get(id=request.session['user_id']))
    return redirect('/')

def comment(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    poster = User.objects.get(id=request.session['user_id'])
    message = Comment_Thread.objects.get(id=post_id)
    Reply.objects.create(comment=request.POST['reply'], poster = poster, original_post = message)
    return redirect('/success')

def profile(request, user_id):
    context = {
        'user': User.objects.get(id=user_id)
    }
    
    return render(request, 'profile.html', context)

def add_like(request, id):
    if 'user_id' not in request.session:
        return redirect('/')
    liked_message = Comment_Thread.objects.get(id=id)
    user_liking = User.objects.get(id=request.session['user_id'])
    liked_message.user_likes.add(user_liking)
    return redirect('/success')