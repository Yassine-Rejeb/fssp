from django.db import models
from django.utils import timezone
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class userAccount(models.Model):
    username = models.CharField(max_length=50)
    fullname = models.CharField(max_length=50)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=512)
    profilePic = models.ImageField(upload_to='profilePics/', default='profilePics/default.jpg')
    accountCreationTime = models.DateTimeField(default=timezone.now)
    status2FA = models.BooleanField()
    criticalLockStat = models.BooleanField()
    idleTime = models.IntegerField()
    verified = models.BooleanField(default=False)
    forgotPasswordKey = models.CharField(max_length=6, default="")
    forgotPasswordTimestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.username
    
    def getFullname(self):
        return self.fullname
    
    def getEmail(self):
        return self.email
    
    def getPassword(self):
        return self.password
    
    def getProfilePic(self):
        return self.profilePic
    
    def getStatus2FA(self):
        return self.status2FA
    
    def getCriticalLockStat(self):
        return self.criticalLockStat
    
    def getIdleTime(self):
        return self.idleTime
    
    def setFullname(self, fullname):
        self.fullname = fullname
    
    def setEmail(self, email):
        self.email = email

    def setPassword(self, password):
        import hashlib
        self.password = hashlib.sha512(password.encode()).hexdigest()
    
    def setProfilePic(self, profilePic):
        self.profilePic = profilePic
    
    def setStatus2FA(self, status2FA):
        self.status2FA = status2FA

    def setCriticalLockStat(self, criticalLockStat):
        self.criticalLockStat = criticalLockStat
    
    def setIdleTime(self, idleTime):
        self.idleTime = idleTime

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
    #AESKey = models.CharField(max_length=512)
    
    class Meta:
        db_table = "object"
        ordering = ['dateTimeCreated']

class secret(object):
    secretID = models.AutoField(primary_key=True)
    secretName = models.CharField(max_length=50, default="Untitled")
    content = models.CharField(max_length=40976)

    def __str__(self):
        return self.content

    def getContent(self):
        return self.content

class file(object):
    fileID = models.AutoField(primary_key=True)
    myFile = models.FileField(upload_to='files/')
    fileName = models.CharField(max_length=50)
    size = models.IntegerField()
    
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
    timestamp = models.DateTimeField()
    operation = models.CharField(max_length=250)
    object = models.ForeignKey(object, on_delete=models.CASCADE)    

    def __str__(self):
        return self.operation

    def getUser(self):
        return self.user

    def getTimestamp(self):
        return self.timestamp

    def getOperation(self):
        return self.operation

    def getObject(self):
        return self.object

    class Meta:
        db_table = "notification"
        ordering = ['timestamp']

class activityLog(models.Model):
    objID = models.AutoField(primary_key=True)
    object = models.ForeignKey(object, on_delete=models.PROTECT)
    user = models.ForeignKey(userAccount, on_delete=models.PROTECT)
    timestamp = models.DateTimeField()
    operation = models.CharField(max_length=250)

    def __str__(self):
        return self.operation

    def getObject(self):
        return self.object

    def getUser(self):
        return self.user

    def getTimestamp(self):
        return self.timestamp

    def getOperation(self):
        return self.operation

    class Meta:
        db_table = "activityLog"
        ordering = ['timestamp']

class share(models.Model):
    shareID = models.AutoField(primary_key=True)
    owner = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    object = models.ForeignKey(object, on_delete=models.CASCADE)
    sharedWith = models.ForeignKey(userAccount, on_delete=models.CASCADE, related_name='sharedWith')
    shareDateTime = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.permission

    def getOwner(self):
        return self.owner

    def getObject(self):
        return self.object

    def getPermission(self):
        return self.permission

    class Meta:
        
        ordering = ['owner']

class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) +
            str(user.status2FA) + str(user.idleTime)
        )
    
    def check_token(self, user, token):
        return super().check_token(user, token)
        

