from __future__ import unicode_literals
from django.db import models
from datetime import datetime
from dateutil.relativedelta import relativedelta

import re
import bcrypt

NAME_REGEX = re.compile(r'^[A-Za-z ]*$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

# model manager and validators 
class UserManager(models.Manager):
    def validate_registration_data(self, post_data):
        response = {
            'status' : True
        }
        errors = []

        if len(post_data['name']) < 3:
            errors.append("Name must be at least 3 characters long")

        if not re.match(NAME_REGEX, post_data['name']):
            errors.append('Name may only contain characters')

        if len(post_data['first_name']) < 3:
            errors.append("First name must be at least 3 characters long")

        if not re.match(NAME_REGEX, post_data['first_name']):
            errors.append('First name may only contain characters')

        if len(post_data['last_name']) < 3:
            errors.append("Last name must be at least 3 characters long")

        if not re.match(NAME_REGEX, post_data['last_name']):
            errors.append('Last name may only contain characters')

        if len(post_data['username']) < 3:
            errors.append("Username must be at least 3 characters long")

        if not re.match(NAME_REGEX, post_data['username']):
            errors.append('username may only contain characters')

        if len(post_data['alias']) < 3:
            errors.append("Alias must be at least 3 characters long")

        if not re.match(NAME_REGEX, post_data['alias']):
            errors.append('Alias may only contain characters')

        if len(post_data['email']) < 3:
            errors.append("Email must be at least 3 characters long")

        if not re.match(EMAIL_REGEX, post_data['email']):
            errors.append('Email not valid')

       # does this email already exist?
        users = User.objects.filter(email = post_data['email'])
        if len(users) > 0:
            errors.append('This email is already in use')

        if len(post_data['password']) < 8:
            errors.append("Password must be at least 8 characters long")

        if post_data['password'] != post_data['pwd_confirm']:
            errors.append("Passwords do not match!")

        if len(post_data['dob']) < 8:
            errors.append("Date of Birth is a required field")

        current_date = datetime.now()
        nowDate = current_date.strftime("%Y-%m-%d")

        if nowDate < post_data['dob']:
            errors.append("Date of Birth must be in the past")

        try:
            if datetime.strptime(post_data['dob'], '%Y-%m-%d') > datetime.now() - relativedelta(years=13):
                errors.append("You must be at least 13 years old")
        except ValueError:
            errors.append("Please enter a valid date")

        if len(post_data['start_time']) < 1:
            errors.append("Please enter a valid start time")

        if len(post_data['end_time']) < 1:
            errors.append("Please enter a valid end time")

        if post_data['start_time'] > post_data['end_time']:
            errors.append("Start time must be before end time")

        if len(errors) > 0:
            response['status'] = False
            response['errors'] = errors
        else:
            hashedpwd = bcrypt.hashpw((post_data['password'].encode()), bcrypt.gensalt(5))

            user = User.objects.create(
                name        = post_data['name'],
                first_name  = post_data['first_name'],
                last_name   = post_data['last_name'],
                username    = post_data['username'],
                alias       = post_data['alias'], 
                email       = post_data['email'],
                dob         = post_data['dob'],
                start_time  = post_data['start_time'],
                end_time    = post_data['end_time'],
                password    = hashedpwd)

            response['user'] = user
            
        return response

    def validate_login_data(self, post_data):
        response = {
            'status' : True
        }
        errors = []
        hashedpwd = bcrypt.hashpw((post_data['password'].encode()), bcrypt.gensalt(5))

        user = User.objects.filter(email = post_data['email'])

        if len(user) > 0:
            # check this user's password
            user = user[0]
            if not bcrypt.checkpw(post_data['password'].encode(), user.password.encode()):
                errors.append('email/password incorrect')
        else:
            errors.append('email does not exist - please register')

        if len(errors) > 0:
            response['status'] = False
            response['errors'] = errors
        else:
            response['user'] = user
        return response

# Models
class User(models.Model):
    name        = models.CharField(max_length=255)
    first_name  = models.CharField(max_length=255)
    last_name   = models.CharField(max_length=255)
    username    = models.CharField(max_length=255)
    alias       = models.CharField(max_length=255)
    email       = models.CharField(max_length=255)
    start_time  = models.TimeField()
    end_time    = models.TimeField()
    dob         = models.DateField()
    password    = models.CharField(max_length=255)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now_add=True)
    objects     = UserManager()
