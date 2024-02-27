from django.db import models

class userAccount(models.Model):
    username = models.CharField(max_length=50)
    fullname = models.CharField(max_length=50)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=50)
    profilePic = models.ImageField(upload_to='profilePics/')
    status2FA = models.BooleanField()
    criticalLockStat = models.BooleanField()
    idleTime = models.IntegerField()
    verified = models.BooleanField(default=False)

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
        # db_table = "userAccount"
        ordering = ['fullname']

class object(models.Model):
    OId = models.AutoField(primary_key=True)
    owner = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    dateTimeCreated = models.DateTimeField()

class secret(object):
    secretID = models.AutoField(primary_key=True)
    content = models.CharField(max_length=4100)

    def __str__(self):
        return self.content

    def getContent(self):
        return self.content

class file(object):
    fileID = models.AutoField(primary_key=True, default=0)
    myFile = models.FileField(upload_to='files/')
    fileName = models.CharField(max_length=50)
    size = models.IntegerField()
    
    class Meta:
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
        ordering = ['timestamp']

class session(models.Model):
    sessionId = models.AutoField(primary_key=True)
    user = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    loginTime = models.DateTimeField()
    logoutTime = models.DateTimeField()
    status = models.BooleanField()
    duration = models.DurationField()

    def __str__(self):
        return self.user

    def getUser(self):
        return self.user

    def getLoginTime(self):
        return self.loginTime

    def getLogoutTime(self):
        return self.logoutTime

    def getStatus(self):
        return self.status

    class Meta:
        ordering = ['loginTime']

class share(models.Model):
    shareID = models.AutoField(primary_key=True)
    owner = models.ForeignKey(userAccount, on_delete=models.CASCADE)
    object = models.ForeignKey(object, on_delete=models.CASCADE)
    sharedWith = models.ForeignKey(userAccount, on_delete=models.CASCADE, related_name='sharedWith')

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
