from django.contrib import admin

from .models import userAccount
from .models import secret
from .models import file
from .models import notification
# from .models import session
from .models import share

admin.site.register(userAccount)
admin.site.register(secret)
admin.site.register(file)
admin.site.register(notification)
# admin.site.register(session)
admin.site.register(share)
# Register your models here.