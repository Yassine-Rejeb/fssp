### Sterializers for the models ###
from rest_framework import serializers


class userAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = userAccount
        fields = '__all__'

class emailVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = emailVerification
        fields = '__all__'
    
class objectSerializer(serializers.ModelSerializer):
    class Meta:
        model = object
        fields = '__all__'

class secretSerializer(serializers.ModelSerializer):
    class Meta:
        model = secret
        fields = '__all__'
    
class fileSerializer(serializers.ModelSerializer):
    class Meta:
        model = file
        fields = '__all__'
    
class notificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = notification
        fields = '__all__'

class activityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = activityLog
        fields = '__all__'

# class sessionSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = session
#         fields = '__all__'
    
class shareSerializer(serializers.ModelSerializer):
    class Meta:
        model = share
        fields = '__all__'

