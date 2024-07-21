from .models import userAccount, emailVerification, CustomTokenGenerator
from .models import share, secret, object, eventLog, notification, viewedNotifications
from .models import file as myfile
from fssp_django.settings import client, KUBE_MANAGER_URL

from django.forms.models import model_to_dict

from django.utils import timezone
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from datetime import timedelta

from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.decorators import login_required
from django.utils.encoding import force_str
from django.middleware import csrf

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from datetime import datetime
import requests
import string
import json
import os

from base64 import b64encode, b64decode
import paramiko
import re
import random
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# This is the index page of the API
def index(request):
    return JsonResponse({"message": "Welcome to the FSSP API!"})

# This endpoint is used to get the user details
def getUserDetails(request):
    try:
        # check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        #print("SESSION: ", request.session.items())
        username = userAccount.objects.get(pk=request.session['user']).username
        fullname = userAccount.objects.get(pk=request.session['user']).fullname
        email = userAccount.objects.get(pk=request.session['user']).email
        # profilePic = userAccount.objects.get(pk=request.session['user']).profilePic
        status2FA = userAccount.objects.get(pk=request.session['user']).status2FA
        criticalLockStat = userAccount.objects.get(pk=request.session['user']).criticalLockStat
        idleTime = userAccount.objects.get(pk=request.session['user']).idleTimer

        # Return the user details
        return JsonResponse({"username": username, "fullname": fullname, "email": email, "status2FA": status2FA, "criticalLockStat": criticalLockStat, "idleTime": idleTime})
    except Exception as e:
        print("EXCEPTION in getUserDetails: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to get the user's profile picture
def getProfilePic(request):
    try:
        # check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        profilePic = userAccount.objects.get(pk=request.session['user']).profilePic
        # Convert the bytes object to a base64 encoded string
        base64_profilePic = b64encode(profilePic.read()).decode('utf-8')
        # Return the base64 encoded string as an HttpResponse
        return FileResponse( base64_profilePic , content_type="image/jpeg")
    except Exception as e:
        print("EXCEPTION in getProfilePic: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to check if there is a session/authenticated user
def check_session(request):
    try:
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() < expiry:
                return JsonResponse({"message": "Session exists"})
            else:
                return JsonResponse({"message": "Session expired"})
        return JsonResponse({"message": "Session does not exist"})
    except Exception as e:
        print("EXCEPTION in check_session: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to get a NEW csrf token (for usage with forms in the vuejs frontend)
def genCSRFToken(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})

        # Obtain the CSRF token
        csrf_token = csrf.get_token(request)
        # Save the token in the session
        request.session['csrftoken'] = csrf_token
        print("CSRF TOKEN: ", csrf_token, "len: ", len(csrf_token))
        # Return the token in a JSON response
        return JsonResponse({'csrf_token': csrf_token})
    except Exception as e:
        print("EXCEPTION in genCSRFToken: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to get the CURRENT csrf token 
def getCSRFToken(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})

        # Obtain the CSRF token from the session
        csrftoken = request.session['csrftoken']
        # Return the token in a JSON response
        return JsonResponse({'csrftoken': csrftoken})
    except Exception as e:
        print("EXCEPTION in getCSRFToken: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})
    
# This method is used to send an email to the user
def sendEmail(email, subject, msg):
    try:
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
    except Exception as e:
        print("EXCEPTION in sendEmail: An error occurred while processing your data:", e)

# This method is used to send a verification email to the user
def sendVerificationEmail(user, email):
    try:
        # Set the token expiration time (e.g., 24 hours)
        token_expiration = timezone.now() + timedelta(hours=24)

        # Generate a token for the user with expiration
        token = CustomTokenGenerator().make_token(user)
        token += f'_{int(token_expiration.timestamp())}'

        # Create a unique link for verification
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        url= os.environ.get('VUE_APP_DJANGO_API_SERVER_URL', 'http://django-api.default:30080/')
        verification_link = f'{url}/verify-email/{uidb64}/{token}/'

        # Check for successive slashes : // in the URL
        verification_link = re.sub(r'(?<!:)//', '/', verification_link)

        # Save the verification link to the database
        emailVerification.objects.create(user=user, timestamp=timezone.now(), token=token, uid=uidb64)

        message =   f"""Your account has been successfully created within FSSP system.
        This one-time verification link is accessible for only 4 hours since the creation of your account: {verification_link}"""
        
        # Send the email
        sendEmail(email, "FSSP Email Verification", message)
    except Exception as e:
        print("EXCEPTION in sendVerificationEmail: An error occurred while processing your data:", e)

# This method is used to create a key-pair for the user in Azure Key Vault
def createUserKeyPair(user):
    try:
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
    except Exception as e:
        print("EXCEPTION in createUserKeyPair: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while creating the key-pair"})

# This method is used to verify the email of the user
@csrf_exempt
def verifyEmail(request, uidb64, token):
    try:
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
    except Exception as e:
        print("EXCEPTION in verifyEmail: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while verifying the email"}) 

# This method is create a new user account
@csrf_exempt
def register(request):
    try:
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
        newUser = userAccount(username=username, fullname=fullname, email=email, password=password, status2FA=False, criticalLockStat=False, idleTimer=3600, sessionTimer=30)
        newUser.save()
        sendVerificationEmail(newUser, email)
        return JsonResponse({"message": "user account created successfully"})
    except Exception as e:
        print("EXCEPTION in register: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to login a user
@csrf_exempt
def login(request):
    try:
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
        sessionTime = userAccount.objects.get(email=email).sessionTimer

        # Create a new session
        request.session['expires'] = datetime.now().timestamp() + sessionTime * 60
        request.session['user'] = userAccount.objects.get(email=email).pk 

        # print("SESSION: ", request.session.items())

        # Save the session
        request.session.save()

        return JsonResponse({"message": "login successful"})
    except Exception as e:
        print("EXCEPTION in login: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to enable a user to change his email address ONLY if the user has not yet verified his previous email address
@csrf_exempt
def changeUnverifiedEmail(request):
    try:
        # Get the data from the request
        currntEmail = request.POST.get('current_email')
        password = request.POST.get('password')
        newEmail = request.POST.get('new_email')

        # print("CURRENT EMAIL: ", currntEmail)
        # print("PASSWORD: ", password)
        # print("NEW EMAIL: ", newEmail)

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

        # Remove the previous verification email object from the database if it exists
        emailVerification.objects.get(user=userAccount.objects.get(email=newEmail)).delete()

        # Send the verification email
        sendVerificationEmail(user, newEmail)

        return JsonResponse({"message": "Email updated successfully"})
    except Exception as e:
        print("EXCEPTION in changeUnverifiedEmail: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to logout a user from the system (Remove the session)
def logout(request):
    try:
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
    except Exception as e:
        print("EXCEPTION in logout: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to send a forgot password email to the user (Requires CHANGES)
def sendForgotPassMail(request):
    try:
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
    except Exception as e:
        print("EXCEPTION in sendForgotPassMail: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# Reset the password of the user
def resetPassword(request):
    try:
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
    except Exception as e:
        print("EXCEPTION in resetPassword: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# Encrypt with user's public key
def pubEncrypt(user, plain):
    try:
        # According to the env variable AZURE_MANAGED_IDENTITY
        managed = os.environ.get('AZURE_MANAGED_IDENTITY', 'False')
        if not managed:
            # The following is a static implementation of the encryption process using the auto generated key-pair in the ./ssl directory
            public_key = RSA.import_key(open("./ssl/.crt.crt").read())
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted = cipher_rsa.encrypt(plain)
            return encrypted
        else:
            # Get the public key of the user from the key vault
            publicKey = client.get_secret("publicKey-"+str(user.pk)).value
            
            # Import the public key
            public_key = RSA.import_key("ssh-rsa "+publicKey)
            
            # Create an RSA cipher object with OAEP padding
            cipher_rsa = PKCS1_OAEP.new(public_key)
            
            # Encrypt the plain text
            encrypted = cipher_rsa.encrypt(plain)
            
            return encrypted
    except Exception as e:
        print("EXCEPTION in pubEncrypt: ", e)

# Decrypt with user's private key
def privDecrypt(user, encrypted):
    try:
        # According to the env variable AZURE_MANAGED_IDENTITY
        managed = os.environ.get('AZURE_MANAGED_IDENTITY', 'False')
        if not managed:
            # The following is a static implementation of the decryption process using the auto generated key-pair in the ./ssl directory
            private_key = RSA.import_key(open("./ssl/.crt.key").read())
            cipher_rsa = PKCS1_OAEP.new(private_key)
            plain = cipher_rsa.decrypt(encrypted)
            return plain
        else:
            # Get the private key of the user from the key vault
            privateKey = client.get_secret("privateKey-"+str(user.pk)).value
            
            # Import the private key
            private_key = RSA.import_key(privateKey)
            
            # Create an RSA cipher object with OAEP padding
            cipher_rsa = PKCS1_OAEP.new(private_key)
            
            # Decrypt the plain text
            plain = cipher_rsa.decrypt(encrypted)
            
            return plain
    except Exception as e:
        print("EXCEPTION in privDecrypt: ", e)
    
# This endpoint is used to create a new secret
@csrf_protect
def addSecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})

        # Check if the Form data is in the request body
        if request.body is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the form data from the request
        data = json.loads(request.body)
        secret_name = data.get('secret_name')
        secret_content = data.get('secret_content')

        # Check if the form data is empty
        if secret_name is None or secret_content is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret name is already taken
        if secret.objects.filter(secretName=secret_name, owner=user).exists():
            return JsonResponse({"message": "Secret name already taken"})

        # Generate the AES key using a CSPRNG
        AESKey_plain = get_random_bytes(16)

        # Encrypt the AES key with the user's public key
        encrypted_aes_key = pubEncrypt(user, AESKey_plain)

        # Encrypt the content with the AES key
        cipher = AES.new(AESKey_plain, AES.MODE_CBC)
        iv = cipher.iv
        # print("IV: ", len(iv))
        # print("IV: ", iv)
        # print("B64 IV: ", b64encode(iv))
        # Pad the content to match the block size of AES using PKCS#7 padding
        content_padded = pad(secret_content.encode(), AES.block_size, style='pkcs7')

        # Encrypt the padded content
        cipher_text = cipher.encrypt(content_padded)

        # Create a new secret
        newSecret = secret(owner=user, dateTimeCreated=timezone.now(), AESKey=b64encode(encrypted_aes_key).decode('utf-8'), content=b64encode(cipher_text).decode('utf-8'), iv=b64encode(iv) , secretName=secret_name)
        newSecret.save()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Created a secret", object=newSecret)
        newEvent.save()
        # Add notification 
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Created a secret", objectType="secret", objectName=secret_name)
        newNotif.save()

        return JsonResponse({"message": "Secret created successfully"})
    except Exception as e:
        print("EXCEPTION in addSecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to list all secrets owned by a user
def listSecrets(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        user = userAccount.objects.get(pk=request.session['user'])
        
        # Get all the secrets relevant to the user
        secrets = list(secret.objects.filter(owner=user).values())
        
        # Get the AES encrypted key and content from DB decrypt the AES_Encrypted 
        # key with the private key and then decrypt the content with the AES key
        for i in secrets:
            if i['secretName'] != "secret2":
                continue
            # Decrypt the AES key
            decrypted_aes_key = privDecrypt(user, b64decode(i['AESKey']))
            # print("Decrypted AES Key: ", decrypted_aes_key)

            # Get the IV
            iv = i['iv'][2:-1] # cause it's saved as b'iv' in the database
            iv = b64decode(iv)
            
            # Decrypt the content with the AES key
            cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv=iv)

            # Decrypt the padded content
            content_padded = cipher.decrypt(b64decode(i['content']))

            # Unpad the content using the PKCS7 padding scheme
            secret_content = unpad(content_padded, AES.block_size, style='pkcs7').decode()

            # Update the secrets with the decrypted content
            i['content'] = secret_content

        # Create a json object that contains: Secret Name, DatetimeCreated, SharedWith 
        r = list()
        for i in secrets:
            if share.objects.filter(object=secret.objects.get(pk=i['secretID'])):
                sharedWith = list(share.objects.filter(object=secret.objects.get(pk=i['secretID'])).values())
                for j in sharedWith:
                    j['sharedWith'] = userAccount.objects.get(pk=j['sharedWith_id']).username
                sw = sharedWith
            else:
                sw = []
            r.append({"SecretID":i['secretID'],"SecretName": i['secretName'], "DatetimeCreated": i['dateTimeCreated'], "SharedWith": sw})

        # Return the secrets
        return JsonResponse(r, safe=False)
    except Exception as e:
        print("EXCEPTION in listSecrets: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to share a secret with a user via username
def shareSecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            print("SESSION: ", request.session.__dict__)
            return JsonResponse({"message": "Unauthorized access"})

        # Get the form data from the request
        secretID = request.GET.get('secret_id')
        username = request.GET.get('username')
        oneTimeShare = request.GET.get('one_time_share')
        shareValidity = request.GET.get('share_time_period')
        csrftoken = request.GET.get('csrftoken')

        if oneTimeShare == "true":
            oneTimeShare = True
        else: 
            oneTimeShare = False

        # Check CSRF Protection
        if csrftoken != request.session['csrftoken']:
            # print("CSRF Received: ", csrftoken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # print("SECRET ID: ", secretID)
        # print("USERNAME: ", username)

        # Check if the Form data is in the request body
        if secretID is None or username is None:
            return JsonResponse({"message": "Form data not found"})

        # Check if one time share is enabled along with the share time period
        if oneTimeShare == True and int(shareValidity) > 0:
            print(oneTimeShare, shareValidity)
            return JsonResponse({"message": "Conflicting options"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret exists
        if not secret.objects.filter(secretID=secretID).exists():
            return JsonResponse({"message": "Secret does not exist"})

        # Check if the user exists
        if not userAccount.objects.filter(username=username).exists():
            return JsonResponse({"message": "User does not exist"})

        # Check if the Validity Period is valid
        if int(shareValidity) != 0:
            try:
                shareValidity = int(shareValidity)
                if shareValidity < 5 or shareValidity > 10080:
                    return JsonResponse({"message": "Invalid share time period"}) 
            except ValueError:
                return JsonResponse({"message": "Invalid share time period"})

        # Check if the user trying to share secret with himself
        if userAccount.objects.get(username=username) == user:
            return JsonResponse({"message": "Cannot share secret with yourself"})

        # Get the user to share the secret with
        userToShare = userAccount.objects.get(username=username)

        # Check if the user owns the secret to be shared
        if secret.objects.get(secretID=secretID).owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Check if the secret is already shared with the user
        try:
            if share.objects.filter(object=secret.objects.get(secretID=secretID), sharedWith=userToShare).exists():
                return JsonResponse({"message": "Secret already shared with user"})
        except share.DoesNotExist:
            print("Exception: Seeked share does not exist")
        
        # Share the secret with the user
        newShare = share(object=secret.objects.get(secretID=secretID), sharedWith=userToShare, owner=user, oneTimeShare=oneTimeShare, shareValidity=shareValidity)
        newShare.save()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Shared a secret with "+ userToShare.username , object=secret.objects.get(secretID=secretID))
        newEvent.save()
        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Shared with user: "+ userToShare.username , objectType="secret", objectName=secret.objects.get(secretID=secretID).secretName)
        newNotif.save()

        return JsonResponse({"message": "Secret shared successfully"})
    except Exception as e:
        print("EXCEPTION in shareSecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to unshare a secret with a user via username
def revokeSecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        secretID = request.GET.get('secret_id')
        username = request.GET.get('username')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            # print("CSRF Received: ", csrfToken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if secretID is None or username is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret exists
        if not secret.objects.filter(secretID=secretID).exists():
            return JsonResponse({"message": "Secret does not exist"})

        # Check if the user exists
        if not userAccount.objects.filter(username=username).exists():
            return JsonResponse({"message": "User does not exist"})

        # Get the user to unshare the secret with
        userToUnshare = userAccount.objects.get(username=username)

        # Check if the user owns the secret to be unshared
        if secret.objects.get(secretID=secretID).owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Check if the secret is already shared with the user
        try:
            if not share.objects.filter(object=secret.objects.get(secretID=secretID), sharedWith=userToUnshare).exists():
                return JsonResponse({"message": "Secret not shared with user, Nothing is done!"})
        except share.DoesNotExist:
            print("Exception: Seeked share does not exist")
        # Unshare the secret with the user
        share.objects.get(object=secret.objects.get(secretID=secretID), sharedWith=userToUnshare).delete()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Revoked "+userToUnshare.username+"'s access to a secret", object=secret.objects.get(secretID=secretID))
        newEvent.save()

        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Revoked access for user: "+ userToUnshare.username , objectType="secret", objectName=secret.objects.get(secretID=secretID).secretName)
        newNotif.save()

        return JsonResponse({"message": "Secret unshared successfully"})
    except Exception as e:
        print("EXCEPTION in revokeSecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to display a secret
def displaySecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        secretID = request.GET.get('secret_id')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            # print("CSRF Received: ", csrfToken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if secretID is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret exists
        if not secret.objects.filter(secretID=secretID).exists():
            return JsonResponse({"message": "Secret does not exist"})

        # Get the secret
        mySecret = secret.objects.get(secretID=secretID)

        # Check if the user owns the secret
        if mySecret.owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Get the AES encrypted key and content from DB decrypt the AES_Encrypted 
        # key with the private key and then decrypt the content with the AES key
        # Decrypt the AES key
        decrypted_aes_key = privDecrypt(user, b64decode(mySecret.AESKey))
        # print("Decrypted AES Key: ", decrypted_aes_key)

        # Get the IV
        iv = mySecret.iv[2:-1]
        iv = b64decode(iv)
        
        # Decrypt the content with the AES key
        cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv=iv)

        # Decrypt the padded content
        content_padded = cipher.decrypt(b64decode(mySecret.content))

        # Unpad the content using the PKCS7 padding scheme
        secret_content = unpad(content_padded, AES.block_size, style='pkcs7').decode()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Displayed his own secret", object=mySecret)
        newEvent.save()

        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Displayed his own secret", objectType="secret", objectName=mySecret.secretName)
        newNotif.save()

        return JsonResponse({"message": "Secret Retrieved successfully", "secret_content": secret_content})
    except Exception as e:
        print("EXCEPTION in displaySecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to delete a secret
def deleteSecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        secretID = request.GET.get('secret_id')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            # print("CSRF Received: ", csrfToken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if secretID is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret exists
        if not secret.objects.filter(secretID=secretID).exists():
            return JsonResponse({"message": "Secret does not exist"})

        # Get the secret
        mySecret = secret.objects.get(secretID=secretID)

        # Check if the user owns the secret
        if mySecret.owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Delete all shares of the secret
        #share.objects.filter(object=mySecret).delete()

        # Add the eventLog of revoking all shares of the secret to the database
        for i in share.objects.filter(object=mySecret):
            newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Revoked "+i.sharedWith.username+"'s access to a secret", object=mySecret)
            newEvent.save()

        # Check if the secret is being share at the time and the share s not expired
        if share.objects.filter(object=mySecret).exists() and share.objects.get(object=mySecret).shareValidity != 0 and timezone.now() < share.objects.get(object=mySecret).shareDateTime + timedelta(minutes=share.objects.get(object=mySecret).shareValidity):
            
            # Remove the share
            share.objects.get(object=mySecret).delete()

            # Add the eventLog to the database
            newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Deleted his secret that he was sharing", object=mySecret)
            newEvent.save()

            # Add notification
            newNotif = notification(user=user, timestamp=timezone.now(), operation="Deleted his secret that he was sharing", objectType="secret", objectName=mySecret.secretName)
            newNotif.save()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Deleted his secret", object=mySecret)
        newEvent.save()

        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Deleted his secret", objectType="secret", objectName=mySecret.secretName)
        newNotif.save()

        # Delete the secret
        mySecret.delete()
        
        return JsonResponse({"message": "Secret deleted successfully"})
    except Exception as e:
        print("EXCEPTION in deleteSecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

#This endpoint is used to list all secrets shared with a user
def listSharedSecrets(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        user = userAccount.objects.get(pk=request.session['user'])
        
        # Get all the secrets relevant to the user
        shared = list(share.objects.filter(sharedWith=user).values())

        shares = []
        for i in shared:
            if object.objects.filter(OId=i['object_id']).exists() and secret.objects.get(OId=i['object_id']).secretName:
                SecretName = secret.objects.get(OId=i['object_id']).secretName
                shares.append(i)
        
        # Create a json object from the shares variable that contains: Secret Name, DatetimeShared, Owner fullname and username
        result = []
        for i in shares:
            secr = secret.objects.get(OId=i['object_id'])
            owner = userAccount.objects.get(pk=i['owner_id'])
            result.append({"SecretName": secr.secretName, "DatetimeShared": i['shareDateTime'], "OwnerUsername": owner.username, "OwnerFullname": owner.fullname, "SecretID": secr.OId})

        # Return the secrets
        return JsonResponse({"message": "Success", "secrets": result})
    except Exception as e:
        print("EXCEPTION in listSharedSecrets: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to display a shared secret
def displaySharedSecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        secretID = request.GET.get('secret_id')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            # print("CSRF Received: ", csrfToken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if secretID is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret exists
        if not secret.objects.filter(OId=secretID).exists():
            return JsonResponse({"message": "Secret does not exist"})

        # Get the secret
        mySecret = secret.objects.get(OId=secretID)

        # Check if the user has this secret shared with him
        if not share.objects.filter(object=mySecret, sharedWith=user).exists():
            return JsonResponse({"message": "Action not allowed"})
        else:
            myShare = share.objects.get(object=mySecret, sharedWith=user)
        # Make sure to check the validity of the share

        if myShare.shareValidity != 0 and timezone.now() > myShare.shareDateTime + timedelta(minutes=myShare.shareValidity):
            # Remove the share
            share.objects.get(object=mySecret, sharedWith=user).delete()

            # Add the eventLog to the database
            newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Secret share validity expired", object=mySecret)
            newEvent.save()

            # Add notification
            newNotif = notification(user=user, timestamp=timezone.now(), operation="Secret share validity expired", objectType="secret", objectName=mySecret.secretName)
            newNotif.save() 

            return JsonResponse({"message": "The share has expired"})

        # Get the AES encrypted key and content from DB decrypt the AES_Encrypted 
        # key with the private key and then decrypt the content with the AES key
        # Decrypt the AES key
        decrypted_aes_key = privDecrypt(mySecret.owner, b64decode(mySecret.AESKey))
        # print("Decrypted AES Key: ", decrypted_aes_key)

        # Get the IV
        iv = mySecret.iv[2:-1]
        iv = b64decode(iv)
        
        # Decrypt the content with the AES key
        cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv=iv)

        # Decrypt the padded content
        content_padded = cipher.decrypt(b64decode(mySecret.content))

        # Unpad the content using the PKCS7 padding scheme
        secret_content = unpad(content_padded, AES.block_size, style='pkcs7').decode()

        print('one time share: ', myShare.oneTimeShare)
        # If the secret is a one time share, remove the share
        if myShare.oneTimeShare:
            print("Removing one time share")
            share.objects.get(object=mySecret, sharedWith=user).delete()

            # Add the eventLog to the database
            newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Displayed a one time shared secret", object=mySecret)
            newEvent.save()

            # Add notification
            newNotif = notification(user=user, timestamp=timezone.now(), operation="Displayed a one time shared secret", objectType="secret", objectName=mySecret.secretName)
            newNotif.save()

        else:
            # Add the eventLog to the database
            newEvent = eventLog(user=user, timestamp=timezone.now(), operation=f"Displayed a secret shared by "+mySecret.owner.username, object=mySecret)
            newEvent.save()

            # Add notification
            newNotif = notification(user=user, timestamp=timezone.now(), operation=f"Displayed a secret shared by "+mySecret.owner.username, objectType="secret", objectName=mySecret.secretName)
            newNotif.save()

        return JsonResponse({"message": "Secret Retrieved successfully", "secret_content": secret_content})
    except Exception as e:
        print("EXCEPTION in displaySharedSecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to remove access to a shared secret
def removeSharedSecret(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        secretID = request.GET.get('secret_id')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            # print("CSRF Received: ", csrfToken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if secretID is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the secret exists
        if not secret.objects.filter(OId=secretID).exists():
            return JsonResponse({"message": "Secret does not exist"})

        # Get the secret
        mySecret = secret.objects.get(OId=secretID)

        # Check if the user has this secret shared with him
        if not share.objects.filter(object=mySecret, sharedWith=user).exists():
            return JsonResponse({"message": "Action not allowed"})
        
        # Get the share
        myShare = share.objects.get(object=mySecret, sharedWith=user)

        # Remove the share
        myShare.delete()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Removed his own access to a secret shared by "+mySecret.owner.username, object=mySecret)
        newEvent.save()

        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Removed his own access to a secret shared by "+mySecret.owner.username, objectType="secret", objectName=mySecret.secretName)
        newNotif.save()

        return JsonResponse({"message": "Shared Secret removed successfully"})
    except Exception as e:
        print("EXCEPTION in removeSharedSecret: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# this endpoint is used to get all eventLogs relevent to a user and only secrets (not files) 
def getUserEventLogs(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else :
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        try:
            user = userAccount.objects.get(pk=request.session['user'])
        except userAccount.DoesNotExist:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get all the eventLogs relevant to the user
        ## Get eventLogs for events done by the user
        eventLogs = eventLog.objects.filter(user=user).values()
        ## Get eventLogs for events done to the user (or his secrets)
        for event in eventLog.objects.all():
            ops = event.operation.split(" ")
            if user.username in ops:
                eventLogs = eventLogs.union(eventLog.objects.filter(pk=event.pk).values())

        # Create a json object that contains: usename, fullname, operation, timestamp, secret
        data = []
        for log in eventLogs:
            # print(log)
            uid = int(log['user_id'])
            oid = int(log['object_id'])
            data.append({
                "username": userAccount.objects.get(pk=uid).username, 
                "fullname": userAccount.objects.get(pk=uid).fullname, 
                "operation": log['operation'], 
                "secret": secret.objects.get(OId=oid).secretName,
                "date": log['timestamp'], 
            })

        # Replace all instances of the username in the eventLogs with the word "You"
        for i in data:
            if i['username'] == user.username:
                i['username'] = "YOU"
            if user.username in i['operation'].split(" "):
                i['operation'] = i['operation'].replace(user.username, "YOU")

        return JsonResponse({"message": 'Success', 
        'data': data}, safe=False)
    except Exception as e:
        print("EXCEPTION in getUserEventLogs: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to get all notifications relevant to a user
def getNotifications(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        user = userAccount.objects.get(pk=request.session['user'])
        
        # Get the notifications that the last word of the operation is the username of the current user ()
        notifications = notification.objects.filter(operation__endswith=user.username)

        # Now add to that list (notifications) the notifications of object deletion and display of objects shared with the current user
        deletion_notifications = notification.objects.filter(operation__contains="removed")
        for i in deletion_notifications:
            # Check if the secret is shared with the user
            if notification.objects.filter(objectName=i.objectName, operation__contains="shared with user: "+user.username).exists() and not notification.objects.filter(objectName=i.objectName, operation__contains="Revoked access for user: "+user.username).exists():
                notifications = notifications.union(deletion_notifications.filter(objectName=i.objectName))

        display_shared_notifications = notification.objects.filter(operation__contains="Displayed a secret")
        for i in display_shared_notifications:
            if notification.objects.filter(objectName=i.objectName, operation__contains="Displayed a secret shared by "+user.username).exists():
                notifications = notifications.union(display_shared_notifications.filter(objectName=i.objectName))

        display_one_time_shared_notifications = notification.objects.filter(operation__contains="Displayed a one time shared secret")
        for i in display_one_time_shared_notifications:
            if notification.objects.filter(objectName=i.objectName, operation__contains="Displayed a one time shared secret").exists():
                # print("HERE")
                print(display_one_time_shared_notifications.filter(objectName=i.objectName))
                notifications = notifications.union(display_one_time_shared_notifications.filter(objectName=i.objectName))
                # print(notifications)

        expired_share_notifications = notification.objects.filter(operation__contains="Secret share validity expired")
        for i in expired_share_notifications:
            if notification.objects.filter(objectName=i.objectName, operation__contains="Secret share validity expired").exists():
                notifications = notifications.union(expired_share_notifications.filter(objectName=i.objectName))

        # Get the unviewed notifications from that
        final_notifications = []
        for i in notifications:
            if not viewedNotifications.objects.filter(notification=i, user=user).exists():
                final_notifications.append(i)

        # Get the number of notifications
        num_notifications = len(final_notifications)

        # Create a json object that contains: id, usename, operation, timestamp, object type, object name
        data = []
        for i in final_notifications:
            data.append({
                "id": i.NotifID,
                "user": i.user.username,
                "operation": i.operation,
                "object_type": i.objectType,
                "object_name": i.objectName,
                "date": i.timestamp,
            })

        # Replace all instances of the username in the notifications with the word "You"
        for i in data:
            if i['user'] == user.username:
                i['user'] = "YOU"

        return JsonResponse({"message": 'Success',
        'data': data, "count": num_notifications}, safe=False)
    except Exception as e:
        print("EXCEPTION in getNotifications: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to mark a notification
def markNotificationAsViewed(request):
    # Check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    else:
        return JsonResponse({"message": "Unauthorized access"})
    
    try:
        # Get the form data from the request
        csrfToken = request.GET.get('csrfToken')
        nid = request.GET.get('id')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            # print("CSRF Received: ", csrfToken)
            # print("CSRF Session: ", request.session['csrftoken'])
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if nid is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the notification exists
        if not notification.objects.filter(NotifID=nid).exists():
            return JsonResponse({"message": "Notification does not exist"})

        # Get the notification
        myNotification = notification.objects.get(pk=nid)

        # # Check if the notification is relevant to the user
        # if not (myNotification.user == user or myNotification.operation.endswith(user.username)):
        #     print("USER: ", user)
        #     print("NOTIFICATION USER: ", myNotification.user)
        #     print("OPERATION: ", myNotification.operation.endswith(user.username))
        #     return JsonResponse({"message": "Action not allowed"})

        # Mark the notification as viewed
        viewedNotification = viewedNotifications(user=user, notification=myNotification)
        viewedNotification.save()

        return JsonResponse({"message": "Success"})
    except Exception as e:
        print("EXCEPTION in markNotificationAsViewed: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to edit the session expiry time
def editSessionExpiry(request):
    # Check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    else:
        return JsonResponse({"message": "Unauthorized access"})
    
    try:
        # Get the form data from the request body
        data = json.loads(request.body)
        expiry = data.get('expiry')

        # Check if the Form data is in the request body
        if expiry is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the expiry is valid
        try:
            expiry = int(expiry)
            if expiry < 5 or expiry > 720:
                return JsonResponse({"message": "Invalid expiry time, must be between 5 and 720 minutes"}) 
        except ValueError:
            return JsonResponse({"message": "Invalid expiry time, must be between 5 and 720 minutes"})

        # Edit the session expiry time
        request.session['expires'] = datetime.now().timestamp() + (expiry * 60)
        user.sessionTimer = expiry
        user.save()

        return JsonResponse({"message": "Success"})
    except Exception as e:
        print("EXCEPTION in editSessionExpiry: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to get the session expiry time
def getSessionExpiry(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])
        
        # Get the session expiry time from the userAccounts table in the DB
        expiry = userAccount.objects.get(pk=user.pk).sessionTimer

        return JsonResponse({"message": "Success", "expiry": expiry})
    except Exception as e:
        print("EXCEPTION in getSessionExpiry: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to change the password of a user
def changePassword(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})
        # try:
        # Check if the Form data is in the request body
        if request.body is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the form data from the request
        data = json.loads(request.body)
        old_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        confirm_password = data.get('confirmPassword')

        # Check if the form data is empty
        if old_password is None or new_password is None or confirm_password is None:
            print("data", data)
            return JsonResponse({"message": "Form data not found"})

        # Check if the new password and confirm password match
        if new_password != confirm_password:
            return JsonResponse({"message": "Passwords do not match"})

        # Check if the user exists
        if not userAccount.objects.filter(pk=request.session['user']).exists():
            return JsonResponse({"message": "Credentials do not match"})

        # Get the user from session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the old password is correct
        if hashlib.sha512(old_password.encode()).hexdigest() != user.password:
            return JsonResponse({"message": "Credentials do not match"})    

        # Check if the new password is the same as the old password
        if hashlib.sha512(new_password.encode()).hexdigest() == user.password:
            return JsonResponse({"message": "New password cannot be the same as the old password"})

        # Update the password
        user.password = hashlib.sha512(new_password.encode()).hexdigest()
        user.save()

        return JsonResponse({"message": "Password changed successfully"})
        # except Exception as e:
        #     print(e)
        #     return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})
    except Exception as e:
        print("EXCEPTION in changePassword: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to upload and update the profile picture of a user
def changeProfilePic(request):
    # Check if the user is already logged in
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    else:
        return JsonResponse({"message": "Unauthorized access"})
    try:
        print("FILES: ", request.FILES)
        # Check if the Form data is in the request body
        if request.FILES.get('profilePic') is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the form data from the request
        profile_picture = request.FILES.get('profilePic')

        # Check the size of the file (if more than 3MB, refuse it)
        if profile_picture.size > 3000000:
            return JsonResponse({"message": "File size is greater than 3MB"})

        # Check the file type (only acceppt png and jpg)
        if not profile_picture.name.endswith('.png') and not profile_picture.name.endswith('.jpg') and not profile_picture.name.endswith('.jpeg'):
            return JsonResponse({"message": "File type not supported"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Save the file under the name "username_pic.extension"
        profile_picture.name = user.username + "_pic." + profile_picture.name.split('.')[-1]
        print("PROFILE PIC NAME: ", profile_picture.name)
        # Update the profile picture
        user.profilePic = profile_picture
        user.save()

        return JsonResponse({"message": "Profile picture changed successfully"})
    except Exception as e:
        print("EXCEPTION in changeProfilePic: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to add a new file
def addFile(request):
    try: 
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
            return JsonResponse({"message": "Unauthorized access"})

        # Check if the Form data is in the request body
        if request.FILES.get('file') is None:
            return JsonResponse({"message": "Form data not found, File"})
        if request.POST.get('file_name') is None:
            return JsonResponse({"message": "Form data not found, Filename"})
        print("FILES: ", request.FILES.get('file'))
        print("POST: ", request.POST.get('file_name'))
        # Get the form data from the request
        file = request.FILES.get('file')
        filename = request.POST.get('file_name')
        # csrftoken = request.GET.get('csrftoken')

        # Check if the form data is empty
        if file is None or filename is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        print("Size: ", file.size)
        # Check the size of the file (if more than 10MB, refuse it)
        if file.size > 10000000:
            return JsonResponse({"message": "File size is greater than 10MB, denied!"})

        # Dump the file content
        content = file.read()

        # md5 of the content
        md5 = hashlib.md5(content).hexdigest()
        # print("MD5: ", md5)

        # Check if the file already exists
        if myfile.objects.filter(fileHash=filename).exists():
            return JsonResponse({"message": "File already exists"})
        
        # Reset the file pointer
        file.seek(0)
        
        # Send a request to the kube manager to save the file
        resp = requests.post(KUBE_MANAGER_URL + '/upload_file', files={'file': file}, data={'filename': filename, 'username': user.username, 'file_hash': md5})
        print("RESPONSE: ", resp.status_code, resp.text)
        # Get response from the kube manager and process it
        if resp.status_code == 200:
            # Save the file
            newFile = myfile(owner=user, fileName=filename, fileHash=md5, podName=json.loads(resp.text)['podname'], size=file.size, encSize=-1, dateTimeCreated=timezone.now())
            newFile.save()
            return JsonResponse({"message": "File added successfully"})
        elif resp.status_code == 500:
            return JsonResponse({"message":"Operation has failed!" ,"debug": "An error occurred while processing your data, If the problem persists, please contact the administrator"})
    except Exception as e:
        print("EXCEPTION in addFile: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to get all files owned by a user
def getFiles(request):
    try:
        # Check if the user is already logged in
        if request.session.session_key is None:
            return JsonResponse({"message": "Unauthorized access"})
        # Check if the session is expired
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else: 
            return JsonResponse({"message": "Unauthorized access"})
        
        # From the request session, get the user
        user = userAccount.objects.get(pk=request.session['user'])
        
        # Get all the files relevant to the user
        files = list(myfile.objects.filter(owner=user).values())
        
        # Create a json object that contains: fileName, dateTimeCreated, size, sharedWith and fileID
        r = []
        for i in files:
            relevant_shares = share.objects.filter(object=myfile.objects.get(fileID=i['fileID'])).values()
            sharedWith = []
            for j in relevant_shares:
                # sharedWith.append(j['sharedWith_id'])
                # Also append the username relevant to that id
                sharedWith.append(userAccount.objects.get(pk=j['sharedWith_id']).username)
            
            r.append({"fileName": i['fileName'], "dateTimeCreated": i['dateTimeCreated'], "size": i['size'], "fileID": i['fileID'], "sharedWith": sharedWith})

        # Return the files
        return JsonResponse({"files": r})
    except Exception as e:
        print("EXCEPTION in getFiles: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to get all files shared with a user
def getSharedFiles(request):
    try:
        # Check if the user is already logged in
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else:
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
    except Exception as e:
        print("EXCEPTION in getSharedFiles: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data, If the problem persists, please contact the administrator"})

# This endpoint is used to share a file with another user
def shareFile(request):
    try:
        # Check if the user is already logged in
        if request.session.session_key is None:
            return JsonResponse({"message": "Unauthorized access"})
        # Check if the session is expired
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else: 
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        fileID = request.GET.get('file_id')
        sharedWith = request.GET.get('shared_with')
        shareValidity = request.GET.get('share_time_period')
        oneTimeShare = request.GET.get('one_time_share')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if fileID is None or sharedWith is None:
            return JsonResponse({"message": "Form data not found"})

        print("fileID: ", fileID)
        print("sharedWith: ", sharedWith)
        print("shareValidity: ", shareValidity)
        print("oneTimeShare: ", oneTimeShare)


        # Check if one time share is enabled along with the share time period
        if oneTimeShare == True and int(shareValidity) > 0:
            print(oneTimeShare, shareValidity)
            return JsonResponse({"message": "Conflicting options"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the user to share with is the same as the owner
        if user.username == sharedWith:
            return JsonResponse({"message": "Cannot share with yourself"})

        # Check if the file exists
        if not myfile.objects.filter(fileID=fileID).exists():
            return JsonResponse({"message": "File does not exist"})

        # Get the file
        myFile = myfile.objects.get(fileID=fileID)

        # Check if the user owns the file
        if myFile.owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Check if the user exists
        if not userAccount.objects.filter(username=sharedWith).exists():
            return JsonResponse({"message": "User does not exist"})

        # Get the user to share with
        sharedWith = userAccount.objects.get(username=sharedWith)

        # Check if the share validity is valid
        shareValidity = int(shareValidity)
        if shareValidity < 0 or shareValidity > 1440:
            return JsonResponse({"message": "Invalid share validity, must be between 0 and 1440 minutes"}) 

        # Check if the one time share is valid
        if oneTimeShare != "true" and oneTimeShare != "false":
            return JsonResponse({"message": "Invalid one time share value, must be true or false"})
        
        if oneTimeShare == "true":
            oneTimeShare = True
        else:
            oneTimeShare = False

        # Share the file
        newShare = share(object=myFile, sharedWith=sharedWith, shareDateTime=timezone.now(), shareValidity=shareValidity, oneTimeShare=oneTimeShare, owner=user)
        newShare.save()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Shared his file with "+sharedWith.username, object=myFile)
        newEvent.save()

        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Shared his file with "+sharedWith.username, objectType="file", objectName=myFile.fileName)
        newNotif.save()

        return JsonResponse({"message": "File shared successfully"})
    except Exception as e:
        print("EXCEPTION in shareFile: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to revoke access to a shared file
def revokeSharedFile(request):
    try:
        # Check if the user is already logged in
        if request.session.session_key is None:
            return JsonResponse({"message": "Unauthorized access"})
        # Check if the session is expired
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else: 
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        fileID = request.GET.get('fileID')
        sharedWith = request.GET.get('shared_with')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if fileID is None or sharedWith is None:
            print("fileID: ", fileID)
            print("sharedWith: ", sharedWith)
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the file exists
        if not myfile.objects.filter(fileID=fileID).exists():
            return JsonResponse({"message": "File does not exist"})

        # Get the file
        myFile = myfile.objects.get(fileID=fileID)

        # Check if the user owns the file
        if myFile.owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Check if the user exists
        if not userAccount.objects.filter(username=sharedWith).exists():
            return JsonResponse({"message": "User does not exist"})

        # Get the user to revoke the share from
        sharedWith = userAccount.objects.get(username=sharedWith)

        # Check if the share exists
        if not share.objects.filter(object=myFile, sharedWith=sharedWith).exists():
            return JsonResponse({"message": "File is not shared with requested user, operation aborted!"})

        # Remove the share
        share.objects.get(object=myFile, sharedWith=sharedWith).delete()

        # Add the eventLog to the database
        newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Revoked "+sharedWith.username+"'s access to a file", object=myFile)
        newEvent.save()

        # Add notification
        newNotif = notification(user=user, timestamp=timezone.now(), operation="Revoked access for user: "+sharedWith.username, objectType="file", objectName=myFile.fileName)
        newNotif.save()

        return JsonResponse({"message": "Shared File revoked successfully"})
    except Exception as e:
        print("EXCEPTION in revokeSharedFile: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to delete a file
def deleteFile(request):
    try:
        # Check if the user is already logged in
        if request.session.session_key is None:
            return JsonResponse({"message": "Unauthorized access"})
        # Check if the session is expired
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else: 
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        fileID = request.GET.get('fileID')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if fileID is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the file exists
        if not myfile.objects.filter(fileID=fileID).exists():
            return JsonResponse({"message": "File does not exist"})

        # Get the file
        myFile = myfile.objects.get(fileID=fileID)

        # Check if the user owns the file
        if myFile.owner != user:
            return JsonResponse({"message": "Action not allowed"})

        # Send a request to the kube manager to delete the file
        headers = {'Content-Type': 'application/json'}
        data = {'pod_name': myFile.podName, 'owner': user.username, 'filename': myFile.fileName}
        resp = requests.delete(KUBE_MANAGER_URL + '/delete_file', headers=headers , data=json.dumps(data))
        print("RESPONSE: ", resp.status_code, resp.text)
        # Get response from the kube manager and process it
        j = JsonResponse({"message": '' })
        if resp.status_code == 200:
            # Delete the file
            myFile.delete()
            j = JsonResponse({"message": "File deleted successfully"})
            return j
        elif resp.status_code == 500:
            j = JsonResponse({"message":"Operation has failed!" ,"debug": "An error occurred while processing your data, If the problem persists, please contact the administrator"})
            return j
        
        print("RESPONSE: ", resp.status_code, resp.text)
        
    except Exception as e:
        print("EXCEPTION in deleteFile: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to download a file
def downloadFile(request):
    # try:
    # Check if the user is already logged in
    if request.session.session_key is None:
        return JsonResponse({"message": "Unauthorized access"})
    # Check if the session is expired
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    else: 
        return JsonResponse({"message": "Unauthorized access"})
    
    # Get the form data from the request
    fileID = request.GET.get('fileID')
    csrfToken = request.GET.get('csrftoken')

    print("fileID: ", fileID)

    # Check CSRF Protection
    if csrfToken != request.session['csrftoken']:
        return JsonResponse({"message": "A possible CSRF attack detected"})

    # Check if the Form data is in the request body
    if fileID is None:
        return JsonResponse({"message": "Form data not found"})

    # Get the user from the session
    user = userAccount.objects.get(pk=request.session['user'])

    # Check if the file exists
    if not myfile.objects.filter(fileID=fileID).exists():
        return JsonResponse({"message": "File does not exist"})

    # Check if the user has permission to get the file
    if not share.objects.filter(object=myfile.objects.get(fileID=fileID), sharedWith=user).exists() and myfile.objects.get(fileID=fileID).owner != user:
        return JsonResponse({"message": "Action not allowed"})

    # Get the file
    myFile = myfile.objects.get(fileID=fileID)

    # Send a request to the kube manager to download the file
    data = {'filename': myFile.fileName, 'owner': user.username, 'podname': myFile.podName}
    resp = requests.get(KUBE_MANAGER_URL + '/get_file?filename='+myFile.fileName+'&owner='+user.username+'&pod_name='+myFile.podName) 
    # print("RESPONSE: ", resp.status_code, resp.text)
    # Get response from the kube manager and process it
    if resp.status_code == 200:
        # Save the file
        response = HttpResponse(resp.content, content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename=' + myFile.fileName
        # Create a tempfile from the response data
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(resp.content)
            temp.flush()
            temp_path = temp.name
            response = FileResponse(temp, as_attachment=True, filename=myFile.fileName)
        # Create the response
        response = FileResponse(open(temp_path, 'rb'), as_attachment=True, filename=myFile.fileName)
        return response
    elif resp.status_code == 500:
        return JsonResponse({"message":"Operation has failed!" ,"debug": "An error occurred while processing your data, If the problem persists, please contact the administrator"})
    print("RESPONSE: ", resp.status_code, resp.text)
    # except Exception as e:
    #     print("EXCEPTION in downloadFile: An error occurred while processing your data:", e)
    #     return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to download a shared file
def downloadSharedFile(request):
    try:
        # Check if the user is already logged in
        if request.session.session_key is None:
            return JsonResponse({"message": "Unauthorized access"})
        # Check if the session is expired
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else: 
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the form data from the request
        fileID = request.GET.get('fileID')
        csrfToken = request.GET.get('csrftoken')

        # Check CSRF Protection
        if csrfToken != request.session['csrftoken']:
            return JsonResponse({"message": "A possible CSRF attack detected"})

        # Check if the Form data is in the request body
        if fileID is None:
            return JsonResponse({"message": "Form data not found"})

        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])

        # Check if the file exists
        if not myfile.objects.filter(OId=fileID).exists():
            return JsonResponse({"message": "File does not exist"})

        # Get the file
        myFile = myfile.objects.get(OId=fileID)

        # Check if the user has permission to get the file
        if not share.objects.filter(object=myFile, sharedWith=user).exists():
            return JsonResponse({"message": "Action not allowed"})

        # Also remove the share if there is a share validity and the time has expired
        if share.objects.filter(object=myFile, sharedWith=user).exists():
            if share.objects.get(object=myFile, sharedWith=user).shareValidity > 0:
                if (timezone.now() - share.objects.get(object=myFile, sharedWith=user).shareDateTime).total_seconds() > share.objects.get(object=myFile, sharedWith=user).shareValidity * 60:
                    share.objects.get(object=myFile, sharedWith=user).delete()
                    return JsonResponse({"message": "Share has expired, file cannot be downloaded"})

        # Send a request to the kube manager to download the file
        data = {'filename': myFile.fileName, 'owner': myFile.owner.username, 'podname': myFile.podName}
        resp = requests.get(KUBE_MANAGER_URL + '/get_file?filename='+myFile.fileName+'&owner='+myFile.owner.username+'&pod_name='+myFile.podName) 
        # print("RESPONSE: ", resp.status_code, resp.text)
        # Get response from the kube manager and process it
        if resp.status_code == 200:
            # Save the file
            response = HttpResponse(resp.content, content_type='application/force-download')
            response['Content-Disposition'] = 'attachment; filename=' + myFile.fileName
            # Create a tempfile from the response data
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp.write(resp.content)
                temp.flush()
                temp_path = temp.name
            
            # Make sure to delete the share after the file has been downloaded if it is a one time share
            if share.objects.filter(object=myFile, sharedWith=user).exists():
                if share.objects.get(object=myFile, sharedWith=user).oneTimeShare:
                    share.objects.get(object=myFile, sharedWith=user).delete()
                    # Add the eventLog to the database
                    newEvent = eventLog(user=user, timestamp=timezone.now(), operation="Downloaded a one time shared file", object=myFile)
                    newEvent.save()
                    # Add notification
                    newNotif = notification(user=user, timestamp=timezone.now(), operation="Downloaded a one time shared file", objectType="file", objectName=myFile.fileName)
                # Also remove the share if there is a share validity and the time has expired
                if share.objects.get(object=myFile, sharedWith=user).shareValidity > 0:
                    if (timezone.now() - share.objects.get(object=myFile, sharedWith=user).shareDateTime).total_seconds() > share.objects.get(object=myFile, sharedWith=user).shareValidity * 60:
                        share.objects.get(object=myFile, sharedWith=user).delete()
                        
            # Create the response
            response = FileResponse(open(temp_path, 'rb'), as_attachment=True, filename=myFile.fileName)
            return response
        elif resp.status_code == 500:
            return JsonResponse({"message":"Operation has failed!" ,"debug": "An error occurred while processing your data, If the problem persists, please contact the administrator"})
        # print("RESPONSE: ", resp.status_code, resp.text)
    except Exception as e:
        print("EXCEPTION in downloadSharedFile: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to get all eventLogs relevent to a user and only files (not secrets)
def getUserEventLogsFiles(request):
    # try:
    # Check if the user is already logged in
    if request.session.session_key is None:
        return JsonResponse({"message": "Unauthorized access"})
    # Check if the session is expired
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    else :
        return JsonResponse({"message": "Unauthorized access"})
    
    # From the request session, get the user
    user = userAccount.objects.get(pk=request.session['user'])
    
    # Get all the eventLogs relevant to the user
    ## Get eventLogs for events done by the user
    eventLogs = eventLog.objects.filter(user=user).values()
    ## Get eventLogs for events done to the user (or his files)
    for event in eventLog.objects.all():
        ops = event.operation.split(" ")
        if user.username in ops or user.username+"'s" in event.operation:
            eventLogs = eventLogs.union(eventLog.objects.filter(pk=event.pk).values())
        # eventlogs = eventLogs.union
    # Create a json object that contains: usename, fullname, operation, timestamp, file
    data = []
    for log in eventLogs:
        # print(log)
        uid = int(log['user_id'])
        oid = int(log['object_id'])
        # print(oid)
        data.append({
            "username": userAccount.objects.get(pk=uid).username,
            "fullname": userAccount.objects.get(pk=uid).fullname,
            "operation": log['operation'],
            "file": myfile.objects.get(OId=oid).fileName,
            "date": log['timestamp'],
        })

    # Replace all instances of the username in the eventLogs with the word "You"
    for i in data:
        if i['username'] == user.username:
            i['username'] = "YOU"
        if user.username in i['operation'].split(" "):
            i['operation'] = i['operation'].replace(user.username, "YOU")

    return JsonResponse({"message": 'Success', 
    'data': data}, safe=False)
    # except Exception as e:
    #     print("EXCEPTION in getUserEventLogsFiles: An error occurred while processing your data:", e)
    #     return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to list shared files with a user
def listSharedFiles(request):
    try:
    # Check if the user is already logged in
        if request.session.session_key is None:
            return JsonResponse({"message": "Unauthorized access"})
        # Check if the session is expired
        if 'expires' in request.session:
            expiry = request.session['expires']
            if datetime.now().timestamp() > expiry:
                return JsonResponse({"message": "Unauthorized access"})
        else :
            return JsonResponse({"message": "Unauthorized access"})
        
        # Get the user from the session
        user = userAccount.objects.get(pk=request.session['user'])
        
        # Get all the files shared with the user
        shared = list(share.objects.filter(sharedWith=user))
        aux = []
        for i in shared:
            if myfile.objects.filter(OId=i.object_id).exists():
                aux.append(model_to_dict(i))

        # Create a json object that contains: fileName, dateTimeCreated, size, sharedWith and fileID
        result = []
        for i in aux:
            # print("Owner username: ", userAccount.objects.get(pk=i['owner']).username)
            # print("File name: ", myfile.objects.get(OId=i['object']).fileName)
            # print("Date shared: ", i['shareDateTime'])
            result.append({
                "FileID": i['object'],
                "OwnerUsername": userAccount.objects.get(pk=i['owner']).username,
                "OwnerFullname": userAccount.objects.get(pk=i['owner']).fullname,
                "FileName": myfile.objects.get(OId=i['object']).fileName,
                "size": myfile.objects.get(OId=i['object']).size,
                "sharedWith": userAccount.objects.get(pk=i['sharedWith']).username,
                "shareValidity": i['shareValidity'],
                "oneTimeShare": i['oneTimeShare'],
                "DatetimeShared": i['shareDateTime'],
            })

        # Return the files
        # print("RESULT: ", result)
        return JsonResponse({"files": result, "message": "Success"})

    except Exception as e:
        print("EXCEPTION in listSharedFiles: An error occurred while processing your data:", e)
        return JsonResponse({"message": "An error occurred while processing your data"})

# This endpoint is used to remove delete a share by the user shared with
def removeSharedFile(request):
    # try:
    # Check if the user is already logged in
    if request.session.session_key is None:
        return JsonResponse({"message": "Unauthorized access"})
    # Check if the session is expired
    if 'expires' in request.session:
        expiry = request.session['expires']
        if datetime.now().timestamp() > expiry:
            return JsonResponse({"message": "Unauthorized access"})
    else :
        return JsonResponse({"message": "Unauthorized access"})
    
    # Get the form data from the request
    fileID = request.GET.get('fileID')
    csrfToken = request.GET.get('csrftoken')

    # Check CSRF Protection
    if csrfToken != request.session['csrftoken']:
        return JsonResponse({"message": "A possible CSRF attack detected"})

    # Check if the Form data is in the request body
    if fileID is None:
        return JsonResponse({"message": "Form data not found"})

    # Get the user from the session
    user = userAccount.objects.get(pk=request.session['user'])

    # Check if the file exists
    if not myfile.objects.filter(OId=fileID).exists():
        return JsonResponse({"message": "File does not exist"})

    # Get the file
    myFile = myfile.objects.get(OId=fileID)

    # Check if the user has permission to get the file
    if not share.objects.filter(object=myFile, sharedWith=user).exists():
        return JsonResponse({"message": "Action not allowed"})

    # Check if the share exists
    if not share.objects.filter(object=myFile, sharedWith=user).exists():
        return JsonResponse({"message": "File is not shared with requested user, operation aborted!"})

    # Get the owner of the share
    owner = share.objects.get(object=myFile, sharedWith=user).owner

    # Remove the share
    share.objects.get(object=myFile, sharedWith=user).delete()

    # Add the eventLog to the database
    newEvent = eventLog(user=owner, timestamp=timezone.now(), operation="Revoked "+user.username+"'s access to a file", object=myFile)
    newEvent.save()

    # Add notification
    newNotif = notification(user=owner, timestamp=timezone.now(), operation="Revoked access for user: "+user.username, objectType="file", objectName=myFile.fileName)
    newNotif.save()

    return JsonResponse({"message": "Shared File Revoked Successfully"})
    # except Exception as e:
    #     print("EXCEPTION in removeSharedFile: An error occurred while processing your data:", e)
    #     return JsonResponse({"message": "An error occurred while processing your data"})