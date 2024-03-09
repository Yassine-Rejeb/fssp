from .models import userAccount, emailVerification, CustomTokenGenerator, file, share

from django.utils import timezone
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from datetime import timedelta

# Create your views here.
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt

import random
import hashlib
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import string
import json
import base64

# This endpoint is used to get the user details
def getUserDetails(request):
    # check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    
    # From the request session, get the user
    #print("SESSION: ", request.session.items())
    username = userAccount.objects.get(pk=request.session['user']).username
    fullname = userAccount.objects.get(pk=request.session['user']).fullname
    email = userAccount.objects.get(pk=request.session['user']).email
    # profilePic = userAccount.objects.get(pk=request.session['user']).profilePic
    status2FA = userAccount.objects.get(pk=request.session['user']).status2FA
    criticalLockStat = userAccount.objects.get(pk=request.session['user']).criticalLockStat
    idleTime = userAccount.objects.get(pk=request.session['user']).idleTime

    # Return the user details
    return JsonResponse({"username": username, "fullname": fullname, "email": email, "status2FA": status2FA, "criticalLockStat": criticalLockStat, "idleTime": idleTime})

# This endpoint is used to get the user profile picture
def getProfilePic(request):
    # check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    # print("SESSION: ", request.session['user'])
    # From the request session, get the user
    profilePic = userAccount.objects.get(pk=request.session['user']).profilePic
    # Convert the bytes object to a base64 encoded string
    base64_profilePic = base64.b64encode(profilePic.read()).decode('utf-8')
    # Return the base64 encoded string as an HttpResponse
    return FileResponse( base64_profilePic , content_type="image/jpeg")

# This endpoint is used to check if there is a session/authenticated user
def check_session(request):

    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() < expiry:
            return JsonResponse({"message": "Session exists"})
        else:
            return JsonResponse({"message": "Session expired"})
    return JsonResponse({"message": "Session does not exist"})

# This method is used to send an email to the user
def sendEmail(email, subject, msg):
    # Get email details from file (JSON)
    with open("smtp_data.json") as file:
        data = json.load(file)
        sender_email = data["email"]
        receiver_email = email
        password = data["password"]

    # Email content
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Email body
    body = msg
    message.attach(MIMEText(body, "plain"))

    # Email server
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, password)
    text = message.as_string()
    server.sendmail(sender_email, receiver_email, text)
    server.quit()

# This method is used to send a verification email to the user
def sendVerificationEmail(user, email):
    # Set the token expiration time (e.g., 24 hours)
    token_expiration = timezone.now() + timedelta(hours=24)

    # Generate a token for the user with expiration
    token = CustomTokenGenerator().make_token(user)
    token += f'_{int(token_expiration.timestamp())}'

    # Create a unique link for verification
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    verification_link = f'http://127.0.0.1:8080/verify-email/{uidb64}/{token}/'

    # Save the verification link to the database
    emailVerification.objects.create(user=user, timestamp=timezone.now(), token=token, uid=uidb64)

    message =   f"""Your account has been successfully created within FSSP system.
                    This one-time verification link is accessible for only 4 hours since the creation of your account: {verification_link}"""
    
    # Send the email
    sendEmail(email, "FSSP Email Verification", message)

# This method is used to create a key-pair for the user in Azure Key Vault
def createUserKeyPair(user):
    # Import the required libraries
    from fssp_django.settings import client

    # Create a new ssh key-pair for the user
    ## Import the required libraries
    import paramiko
    import os

    ## Generate the key-pair
    key = paramiko.RSAKey.generate(2048)
    private_key = ""
    with open("private_key.pem", "w") as f:
        key.write_private_key(f)
    with open("private_key.pem", "r") as f:
        private_key = f.read()
    public_key = key.get_base64()

    # For tracaebility purpose only when developing & debugging, log the keys
    print("Private Key: ", private_key)
    print("Public Key: ", public_key)

    ## Save the key-pair to the key vault
    # Save the private key as a key in the key vault
    client.set_secret("privateKey-"+str(user.pk), private_key)
    # Save the public key
    client.set_secret("publicKey-"+str(user.pk), public_key)

    # Delete the private key from the server
    os.remove("private_key.pem")

    return JsonResponse({"message": "Key-pair created successfully"}) 

# This method is used to verify the email of the user
@csrf_exempt
def verifyEmail(request, uidb64, token):
    # revert the operation "urlsafe_base64_encode(force_bytes(user.pk))"
    uidb64_decoded = force_str(urlsafe_base64_decode(uidb64))
    # Get the user from the database
    user = userAccount.objects.get(pk=uidb64_decoded)
    
    # Check if the user exists
    if not user:
        return JsonResponse({"message": "User does not exist"})
    
    # Check if the user is already verified
    # if user.verified:
    #     return JsonResponse({"message": "Email already verified"})

    # Check if the token is valid
    token_generator = CustomTokenGenerator()
    token = token.split('_')
    #print("TOKEN: ", token[0]+'-'+token[1])
    if not token_generator.check_token(user, token[0]):
        return JsonResponse({"message": "Invalid token"})

    # Check if the token has expired
    if datetime.now().timestamp() > int(token[1]):
        return JsonResponse({"message": "Token expired"})

    # Verify the email
    user.verified = True
    user.save()
    
    # Create a key-pair for the user in Azure Key Vault
    createUserKeyPair(user)

    return JsonResponse({"message": "Email verified successfully"})

# This method is create a new user account
@csrf_exempt
def register(request):
    # Check if user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() < expiry:
            return JsonResponse({"message": "Already logged in"})

    # Get the data from the request
    username = request.POST.get('username')
    fullname = request.POST.get('fullname')
    email = request.POST.get('email')
    password = request.POST.get('password')
    #profilePic = request.FILES.get('profilePic')

    # Check if the username is already taken
    if userAccount.objects.filter(username=username).exists():
        return JsonResponse({"message": "username already taken"})
    
    # Check if the email is already taken
    if userAccount.objects.filter(email=email).exists():
        return JsonResponse({"message": "email already taken"})
    
    # Hash the password
    password = hashlib.sha512(str(password).encode()).hexdigest()

    # Create a new user account
    newUser = userAccount(username=username, fullname=fullname, email=email, password=password, status2FA=False, criticalLockStat=False, idleTime=3600)
    newUser.save()    
    sendVerificationEmail(newUser, email)
    return JsonResponse({"message": "user account created successfully"})

# This endpoint is used to login a user
@csrf_exempt
def login(request):
    # Check if user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() < expiry:
            return JsonResponse({"message": "Already logged in"})

    # Get the data from the request
    email = request.POST.get('email')
    password = request.POST.get('password')

    # Check if the user exists
    if not userAccount.objects.filter(email=email).exists():
        return JsonResponse({"message": "Credentials do not match"})
    
    # Check if the password is correct
    if userAccount.objects.get(email=email).password != hashlib.sha512(password.encode()).hexdigest():
        return JsonResponse({"message": "Credentials do not match"})
    
    # Get the verification time
    VerifTime = emailVerification.objects.get(user=userAccount.objects.get(email=email))
    # Check if the email is verified
    if not userAccount.objects.get(email=email).verified:
        # Check if the verification email has expired
        if (timezone.now() - VerifTime.timestamp).seconds > 14400:
            # Remove the previous verification email object from the database
            emailVerification.objects.get(user=userAccount.objects.get(email=email)).delete()
            sendVerificationEmail(userAccount.objects.get(email=email), email)
            return JsonResponse({"message": "Please verify your email before logging in. We have sent you another verification email."})
        return JsonResponse({"message": "Please verify your email before logging in. The verification email has already been sent to you. If you have made a mistake, please change your email address."})

    # Get the idle time of the user
    idleTime = userAccount.objects.get(email=email).idleTime

    # Create a new session
    request.session['expires'] = datetime.now().timestamp() + idleTime
    request.session['user'] = userAccount.objects.get(email=email).pk 

    # Save the session
    request.session.save()

    # print("SESSION: ", request.session.items())

    # Display the session
    # expiry = request.session['expires']
    # print("SESSION EXPIRY: ", datetime.fromtimestamp(expiry))

    return JsonResponse({"message": "login successful"})

# This endpoint is used to enable a user to change his email address ONLY if the user has not yet verified his previous email address
@csrf_exempt
def changeUnverifiedEmail(request):
    # Get the data from the request
    currntEmail = request.POST.get('current_email')
    password = request.POST.get('password')
    newEmail = request.POST.get('new_email')

    print("CURRENT EMAIL: ", currntEmail)
    print("PASSWORD: ", password)
    print("NEW EMAIL: ", newEmail)

    # Check if the user exists
    if not userAccount.objects.filter(email=currntEmail).exists():
        return JsonResponse({"message": "User does not exist"})
    
    # Check if the password is correct
    if userAccount.objects.get(email=currntEmail).password != hashlib.sha512(password.encode()).hexdigest():
        return JsonResponse({"message": "Credentials do not match"})
    
    # Check if the email is verified
    if userAccount.objects.get(email=currntEmail).verified:
        return JsonResponse({"message": "Email already verified"})
    
    # Check if the new email is already taken
    if userAccount.objects.filter(email=newEmail).exists():
        return JsonResponse({"message": "Email already taken"})

    # Update the email
    user = userAccount.objects.get(email=currntEmail)
    user.email = newEmail
    user.save()

    # Remove the previous verification email object from the database
    emailVerification.objects.get(user=userAccount.objects.get(email=currntEmail)).delete()

    # Send the verification email
    sendVerificationEmail(user, newEmail)

    return JsonResponse({"message": "Email updated successfully"})


def logout(request):
    # Get the data from the request
    sessionKey = request.session.session_key
    # print("SESSION KEY: ", sessionKey)
    # print("SESSION ITEMS", request.session.__dict__, request.session.items())
    # Check if the session has an expires key
    expiry = 0
    if 'expires' in request.session:
        expiry = request.session['expires']
        # print("SESSION EXPIRY: ", datetime.fromtimestamp(expiry))

    # Check if the session exists
    if not sessionKey:
        return JsonResponse({"message": "No session found"})

    # Check if the session is expired
    if datetime.now().timestamp() > expiry and expiry != 0:
        return JsonResponse({"message": "Session expired"})

    # Delete the session
    request.session.flush()
    return JsonResponse({"message": "logout successful"})

def forgotPassword(request):
    # Get the data from the request
    email = request.POST.get('email')

    # Check if the email exists
    if not userAccount.objects.filter(email=email).exists():
        return JsonResponse({"message": "Email not found"})

    # Send the email
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    message = f"Your password reset key is: {key}, It will expire in 10 minutes."
    sendEmail(email, "FSSP Password Reset", message)

    # Save the key to the database
    user = userAccount.objects.get(email=email)
    user.forgotPasswordKey = key
    user.forgotPasswordTimestamp = datetime.now()
    user.save()
    return JsonResponse({"message": "Password reset key sent and will expire in 10 minutes."})

def resetPassword(request):
    # Get the data from the request
    email = request.POST.get('email')
    key = request.POST.get('key')
    newPassword = request.POST.get('newPassword')

    # Check if the email exists
    if not userAccount.objects.filter(email=email).exists():
        return JsonResponse({"message": "Email not found"})

    # Check if the key is correct
    user = userAccount.objects.get(email=email)
    if user.forgotPasswordKey != key:
        return JsonResponse({"message": "Invalid key"})
    
    # Check if the key has expired
    if (datetime.now() - user.forgotPasswordTimestamp).seconds > 600:
        return JsonResponse({"message": "Key has expired"})
    
    # Reset the password
    user.setPassword(newPassword)
    user.save()
    return JsonResponse({"message": "Password reset successfully"})

# This endpoint is used to get all files owned by a user
def getFiles(request):
    # Check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    # From the request session, get the user
    user = userAccount.objects.get(pk=request.session['user'])
    # Get all the files relevant to the user
    files = list(file.objects.filter(owner=user).values())
    # Return the files
    return JsonResponse({"files": files})

# This endpoint is used to get all files shared with a user
def getSharedFiles(request):
    # Check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    # From the request session, get the user
    user = userAccount.objects.get(pk=request.session['user'])
    # Get all the files relevant to the user
    shared = list(share.objects.filter(sharedWith=user).values())
    result = []
    for i in shared:
        if i.object.instance_of == "file":
            result.append(i)
    # Return the files
    return JsonResponse({"files": result})