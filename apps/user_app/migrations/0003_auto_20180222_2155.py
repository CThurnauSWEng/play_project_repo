# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2018-02-22 21:55
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_app', '0002_auto_20180222_2150'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='end_time',
            field=models.TimeField(),
        ),
        migrations.AlterField(
            model_name='user',
            name='start_time',
            field=models.TimeField(),
        ),
    ]