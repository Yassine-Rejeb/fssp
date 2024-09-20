from django.db import models
from django.utils import timezone
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class userAccount(models.Model):
    username = models.CharField(max_length=50)
    fullname = models.CharField(max_length=50)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=512)
    profilePic = models.ImageField(upload_to='./profilePics/', default='profilePics/default.jpg')
    accountCreationTime = models.DateTimeField(default=timezone.now)
    status2FA = models.BooleanField()
    criticalLockStat = models.BooleanField()
    idleTimer = models.IntegerField()
    sessionTimer = models.IntegerField(default=30)
    verified = models.BooleanField(default=False)
    forgotPasswordKey = models.CharField(max_length=6, default="")
    forgotPasswordTimestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.username
    
    class Meta:
        db_table = "userAccount"
        ordering = ['fullname']

class emailVerification(models.Model):
    verificationID = models.AutoField(primary_key=True)
    user = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    token = models.CharField(max_length=64)
    uid = models.CharField(max_length=32)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.key

    def getUser(self):
        return self.user

    def getKey(self):
        return self.key

    def getTimestamp(self):
        return self.timestamp

    class Meta:
        db_table = "emailVerification"
        ordering = ['timestamp']

class object(models.Model):
    OId = models.AutoField(primary_key=True)
    owner = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    dateTimeCreated = models.DateTimeField()
    # AES Key encrypted with RSA public key
    AESKey = models.CharField(max_length=512)
    
    class Meta:
        db_table = "object"
        ordering = ['dateTimeCreated']

class secret(object):
    secretID = models.AutoField(primary_key=True)
    secretName = models.CharField(max_length=50, default="Untitled")
    content = models.CharField(max_length=4097)
    iv = models.CharField(max_length=1024)

    def __str__(self):
        return self.content

    def getContent(self):
        return self.content

class file(object):
    fileID = models.AutoField(primary_key=True)
    podName = models.CharField(max_length=100, default="default")
    fileName = models.CharField(max_length=50)
    size = models.IntegerField(default=-1)
    encSize = models.IntegerField(default=-1)
    fileHash = models.CharField(max_length=33, default="")
    
    class Meta:
        db_table = "file"
        ordering = ['fileName']

    def __str__(self):
        return self.fileName
    
    def getMyFile(self):
        return self.myFile
    
    def getFileName(self):
        return self.fileName

class notification(models.Model):
    user = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    NotifID = models.AutoField(primary_key=True)
    # owner = models.ForeignKey(userAccount, on_delete=models.CASCADE, related_name='owner', null=True)
    timestamp = models.DateTimeField()
    operation = models.CharField(max_length=100)
    objectType = models.CharField(max_length=6, default="object")
    objectName = models.CharField(max_length=50, null=True)
    # viewed = models.BooleanField(default=False)

    class Meta:
        db_table = "notification"
        ordering = ['timestamp']

class viewedNotifications(models.Model):
    vNotID = models.AutoField(primary_key=True)
    notification = models.ForeignKey(notification, on_delete=models.CASCADE)
    user = models.ForeignKey(userAccount, on_delete=models.CASCADE)

    class Meta:
        db_table = "viewedNotifications"

class share(models.Model):
    shareID = models.AutoField(primary_key=True)
    owner = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    object = models.ForeignKey(object, on_delete=models.CASCADE)
    sharedWith = models.ForeignKey(userAccount, on_delete=models.CASCADE, related_name='sharedWith')
    shareDateTime = models.DateTimeField(default=timezone.now)
    oneTimeShare = models.BooleanField(default=False)
    shareValidity = models.IntegerField(default=0) 

    def __str__(self):
        return self.permission

    def getOwner(self):
        return self.owner

    def getObject(self):
        return self.object

    class Meta:
        
        ordering = ['owner']

class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) +
            str(user.status2FA) + str(user.idleTimer)
        )
    
    def check_token(self, user, token):
        return super().check_token(user, token)
        
class eventLog(models.Model):
    eventID = models.AutoField(primary_key=True)
    user = models.ForeignKey(userAccount, on_delete=models.CASCADE, null=True)
    timestamp = models.DateTimeField()
    operation = models.CharField(max_length=250)
    object = models.ForeignKey(object, on_delete=models.CASCADE, null=True)
    viewed = models.BooleanField(default=False)

    def __str__(self):
        return self.operation


