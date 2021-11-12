from django.shortcuts import render, redirect
from django.contrib import messages, admin
from .models import *
from datetime import datetime
import bcrypt

def index(request):
    if 'user_id' in request.session:
        return redirect('/home')
    return render(request, 'login.html')

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

def success(request):
    if 'user_id' not in request.session:
        return redirect('/')
    this_user = User.objects.filter(id=request.session['user_id'])
    context = {
        'user': this_user[0],
    }
    return render(request, 'home.html', context)

def comment(request):
    if 'user_id' not in request.session:
        return redirect('/')
    Comment_Thread.objects.create(
        message=request.POST['message'],
        poster=User.objects.get(id=request.session['user_id'])
        )
    return redirect('/')

def editComment(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    context = {
        'comment': Comment_Thread.objects.get(id=post_id)
    }
    return render(request, 'editComment.html', context)

def updateComment(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    to_update = Comment_Thread.objects.get(id=post_id)
    to_update.message = request.POST['message']
    to_update.save()
    return redirect('/')

def deleteComment(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    to_delete = Comment_Thread.objects.get(id=post_id)
    if request.session['user_id'] != to_delete.poster.id:
        messages.error(request, 'You are not the creator of the comment you are trying to delete!')
        return redirect('/home')
    to_delete.delete()
    return redirect('/home')

def Reply(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    poster = User.objects.get(id=request.session['user_id'])
    message = Comment_Thread.objects.get(id=post_id)
    Reply.objects.create(
        comment=request.POST['reply'],
        poster = poster,
        original_post = message
        )
    return redirect('/success')

def editReply(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    context = {
        'reply': Reply.objects.get(id=post_id)
    }
    return render(request, 'editReply.html', context)

def updateReply(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    to_update = Reply.objects.get(id=post_id)
    to_update.reply = request.POST['reply']
    to_update.save()
    return redirect('/')

def deleteReply(request, post_id):
    if 'user_id' not in request.session:
        return redirect('/')
    to_delete = Reply.objects.get(id=post_id)
    if request.session['user_id'] != to_delete.poster.id:
        messages.error(request, 'You are not the creator of the comment you are trying to delete!')
        return redirect('/home')
    to_delete.delete()
    return redirect('/home')

def add_like(request, id):
    if 'user_id' not in request.session:
        return redirect('/')
    liked_message = Comment_Thread.objects.get(id=id)
    user_liking = User.objects.get(id=request.session['user_id'])
    liked_message.user_likes.add(user_liking)
    return redirect('/success')

def remove_like(request, id):
    if 'user_id' not in request.session:
        return redirect('/')
    liked_message = Comment_Thread.objects.get(id=id)
    user_liking = User.objects.get(id=request.session['user_id'])
    liked_message.user_likes.remove(user_liking)
    return redirect('/success')

def profile(request, user_id):
    context = {
        'user': User.objects.get(id=user_id)
    }
    
    return render(request, 'profile.html', context)

def edit_profile(request, user_id):
    if 'user_id' not in request.session:
        return redirect('/')
    checkID = request.session['user_id']
    if checkID != user_id:
        return redirect('/home')
    context = {
        'user': User.objects.get(id=user_id),
        'loggedIn': request.session['user_id'],
    }
    return render(request, 'editProfile.html', context)

def update_profile(request, user_id):
    if 'user_id' not in request.session:
        return redirect('/')
    checkID = request.session['user_id']
    if checkID != user_id:
        return redirect('/home')
    errors = User.objects.update_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
            return redirect(f'/user/edit/{user_id}')
    to_update = User.objects.get(id=user_id)
    to_update.first_name = request.POST['first_name']
    to_update.last_name = request.POST['last_name']
    to_update.email = request.POST['email']
    to_update.dob = request.POST['dob']
    to_update.location = request.POST['location']
    to_update.save()
    return redirect(f'/user/{user_id}')

def allEvents(request):
    sorted_events = Event.objects.all().order_by('day')
    context = {
        'events': sorted_events,
    }
    return render(request, 'allEvents.html', context)

def event(request, event_id):
    if 'user_id' not in request.session:
        return redirect('/')
    context = {
        'user': User.objects.get(id=request.session['user_id']),
        'event': Event.objects.get(id=event_id),
        'loggedIn': User.objects.get(id=request.session['user_id']),
    }
    return render(request, 'event.html', context)

def createEvent(request):
    if 'user_id' not in request.session:
        return redirect('/')
    now = datetime.today().strftime('%Y-%m-%d')
    errors = Event.objects.event_validator(request.POST)
    if len(errors) != 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/home')
    if request.POST['day'] < now:
        messages.error(request, 'Date cannot be in the past')
        return redirect('/home')
    Event.objects.create(
        title = request.POST['title'],
        description = request.POST['description'],
        sport = request.POST['sport'],
        city = request.POST['city'],
        address = request.POST['address'],
        day = request.POST['day'],
        age_restricted = request.POST['age_restricted'],
        creator = User.objects.get(id=request.session['user_id'])
    )
    return redirect('/home')

def editEvent(request, event_id):
    if 'user_id' not in request.session:
        return redirect('/')
    context = {
        'event': Event.objects.get(id=event_id),
        'loggedIn': User.objects.get(id=request.session['user_id']),
    }
    return render(request, 'editEvent.html', context)

def updateEvent(request, event_id):
    if 'user_id' not in request.session:
        return redirect('/')
    now = datetime.today().strftime('%Y-%m-%d')
    errors = Event.objects.update_event_validator(request.POST)
    if len(errors) != 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect(f'/event/update/{event_id}')
    if request.POST['day'] < now:
        messages.error(request, 'Date cannot be in the past')
        return redirect(f'/event/update/{event_id}')
    to_update = Event.objects.get(id=event_id)
    to_update.title = request.POST['title']
    to_update.description = request.POST['description']
    to_update.sport = request.POST['sport']
    to_update.city = request.POST['city']
    to_update.address = request.POST['address']
    to_update.day = request.POST['day']
    to_update.age_restricted = request.POST['age_restricted']
    to_update.save()
    return redirect('/home')

def deleteEvent(request, event_id):
    if 'user_id' not in request.session:
        return redirect('/')
    to_delete = Event.objects.get(id=event_id)
    if request.session['user_id'] != to_delete.creator.id:
        messages.error(request, 'You are not the creator of the Event you are trying to delete!')
        return redirect('/home')
    to_delete.delete()
    return redirect('/home')

def attendEvent(request, event_id):
    if 'user_id' not in request.session:
        return redirect('/')
    eventToAttend = Event.objects.get(id=event_id)
    userToAttend = User.objects.get(id=request.session['user_id'])
    eventToAttend.attending.add(userToAttend)
    return redirect('/home')

def unattendedEvent(request, event_id):
    if 'user_id' not in request.session:
        return redirect('/')
    loggedIN = request.session['user_id']
    event = Event.objects.get(id=event_id)
    event.attending.remove(loggedIN)
    return redirect('/home')