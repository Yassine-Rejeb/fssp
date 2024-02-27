# Generated by Django 5.0.2 on 2024-02-27 02:13

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_file_fileid_secret_secretid_alter_file_object_ptr_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='objEvent',
            fields=[
                ('objID', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField()),
                ('operation', models.CharField(max_length=250)),
                ('object', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.object')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.useraccount')),
            ],
            options={
                'ordering': ['timestamp'],
            },
        ),
        migrations.CreateModel(
            name='session',
            fields=[
                ('sessionId', models.AutoField(primary_key=True, serialize=False)),
                ('loginTime', models.DateTimeField()),
                ('logoutTime', models.DateTimeField()),
                ('status', models.BooleanField()),
                ('duration', models.DurationField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.useraccount')),
            ],
            options={
                'ordering': ['loginTime'],
            },
        ),
    ]