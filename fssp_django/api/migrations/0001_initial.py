# Generated by Django 5.0.2 on 2024-03-12 08:18

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='object',
            fields=[
                ('OId', models.AutoField(primary_key=True, serialize=False)),
                ('dateTimeCreated', models.DateTimeField()),
                ('AESKey', models.CharField(max_length=512)),
            ],
            options={
                'db_table': 'object',
                'ordering': ['dateTimeCreated'],
            },
        ),
        migrations.CreateModel(
            name='userAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=50)),
                ('fullname', models.CharField(max_length=50)),
                ('email', models.CharField(max_length=50)),
                ('password', models.CharField(max_length=512)),
                ('profilePic', models.ImageField(default='profilePics/default.jpg', upload_to='profilePics/')),
                ('accountCreationTime', models.DateTimeField(default=django.utils.timezone.now)),
                ('status2FA', models.BooleanField()),
                ('criticalLockStat', models.BooleanField()),
                ('idleTime', models.IntegerField()),
                ('verified', models.BooleanField(default=False)),
                ('forgotPasswordKey', models.CharField(default='', max_length=6)),
                ('forgotPasswordTimestamp', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'db_table': 'userAccount',
                'ordering': ['fullname'],
            },
        ),
        migrations.CreateModel(
            name='file',
            fields=[
                ('object_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, to='api.object')),
                ('fileID', models.AutoField(primary_key=True, serialize=False)),
                ('myFile', models.FileField(upload_to='files/')),
                ('fileName', models.CharField(max_length=50)),
                ('size', models.IntegerField()),
            ],
            options={
                'db_table': 'file',
                'ordering': ['fileName'],
            },
            bases=('api.object',),
        ),
        migrations.CreateModel(
            name='secret',
            fields=[
                ('object_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, to='api.object')),
                ('secretID', models.AutoField(primary_key=True, serialize=False)),
                ('secretName', models.CharField(default='Untitled', max_length=50)),
                ('content', models.CharField(max_length=40976)),
                ('iv', models.CharField(max_length=16)),
            ],
            bases=('api.object',),
        ),
        migrations.CreateModel(
            name='share',
            fields=[
                ('shareID', models.AutoField(primary_key=True, serialize=False)),
                ('shareDateTime', models.DateTimeField(default=django.utils.timezone.now)),
                ('object', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.object')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.useraccount')),
                ('sharedWith', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sharedWith', to='api.useraccount')),
            ],
            options={
                'ordering': ['owner'],
            },
        ),
        migrations.AddField(
            model_name='object',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.useraccount'),
        ),
        migrations.CreateModel(
            name='notification',
            fields=[
                ('NotifID', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField()),
                ('operation', models.CharField(max_length=250)),
                ('object', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.object')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.useraccount')),
            ],
            options={
                'db_table': 'notification',
                'ordering': ['timestamp'],
            },
        ),
        migrations.CreateModel(
            name='emailVerification',
            fields=[
                ('verificationID', models.AutoField(primary_key=True, serialize=False)),
                ('token', models.CharField(max_length=64)),
                ('uid', models.CharField(max_length=32)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.useraccount')),
            ],
            options={
                'db_table': 'emailVerification',
                'ordering': ['timestamp'],
            },
        ),
        migrations.CreateModel(
            name='activityLog',
            fields=[
                ('objID', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField()),
                ('operation', models.CharField(max_length=250)),
                ('object', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='api.object')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='api.useraccount')),
            ],
            options={
                'db_table': 'activityLog',
                'ordering': ['timestamp'],
            },
        ),
    ]
