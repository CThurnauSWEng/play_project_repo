from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import User

# the index function is called when root is visited
def index(request):
    return render(request, "user_app/index.html")

def welcome(request):
    context = {
        'this_user'   : User.objects.get(id=request.session['user_id']),
        'other_users' : User.objects.all().exclude(id=request.session['user_id'])
    }
    return render(request, "user_app/welcome.html",context)

def process_login(request):

    response = User.objects.validate_login_data(request.POST)

    if (response['status']):
        request.session['errors']  = []
        request.session['user_id'] = response['user'].id
        return redirect('/user/welcome')
    else:
        for error in response['errors']:
            messages.error(request, error)
        return render(request, "user_app/index.html")


def process_register(request):
    
    # the method validate_registration_data validates the form data and if there
    # are no errors, it also creates the user and returns the user object.
    # if there are errors, it returns a list of them in the response object.

    response = User.objects.validate_registration_data(request.POST)

    if (response['status']):
        request.session['errors']  = []
        request.session['user_id'] = response['user'].id
        return redirect('/user/welcome')
    else:
        for error in response['errors']:
            messages.error(request, error)
        return render(request, "user_app/index.html")

def logout(request):
    request.session['errors']  = []
    request.session['user_id'] = 0
    return render(request, "user_app/index.html")
