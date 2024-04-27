"""
Django settings for fssp_django project.

Generated by 'django-admin startproject' using Django 5.0.2.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-85p#57v7k#u_ggf@%wbl*s63y18nll4x^sptz!u(*=l!9#s18u'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'True') == 'True'

# ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(',')
ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'api',
    'corsheaders',
    'django_extensions',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

SESSION_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SAMESITE = 'None'

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True



ROOT_URLCONF = 'fssp_django.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# USE_SSL = True
# SECURE_SSL_REDIRECT = True

# Paths to the SSL certificate and private key
# SSL_CERTIFICATE = '/ssl/server.crt'
# SSL_PRIVATE_KEY = '/ssl/server.key'


WSGI_APPLICATION = 'fssp_django.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get('POSTGRES_DB_NAME', 'fssp'),
        'USER': os.environ.get('POSTGRES_DB_USER', 'fssp_user'),
        'PASSWORD': os.environ.get('POSTGRES_DB_PASSWORD', 'fssp_passme+.'),
        'HOST': os.environ.get('POSTGRES_DB_HOST', '127.0.0.1'),
        'PORT': '5432',
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_ALLOW_ALL = True
# CORS_ALLOWED_ORIGINS = [
#     'http://vue.fssp.m0d4s.me:8080',
#     'http://drf.fssp.m0d4s.me:8000',
#     'https://django-api.default:30080',
#     'http://127.0.0.1:8080',
#     'http://127.0.0.1:8000',
#     os.environ.get('FRONTEND_SERVICE_URL', 'http://vuejs-service.default.svc.cluster.local')
# ]

CSRF_TRUSTED_ORIGINS = ['http://vue.fssp.m0d4s.me:8080', 'http://127.0.0.1:8080', 'http://localhost:8080', os.environ.get('VUE_APP_DJANGO_API_SERVER_URL', 'http://vuejs-service.default.svc.cluster.local')]

SESSION_SAVE_EVERY_REQUEST = True

SESSION_COOKIE_HTTPONLY = True

# Azure Identity for the Azure Key Vault access from the json file

# ## Init variables
# AZURE_TENANT_ID = ''
# AZURE_CLIENT_ID = ''
# AZURE_CLIENT_SECRET = ''
# AZURE_KEYVAULT_NAME = ''

import json
## Load the Azure Identity from the json file
with open('azure-identity.json') as f:
    data = json.load(f)
    AZURE_KEYVAULT_NAME = data['keyVaultName']
    AZURE_TENANT_ID = data['tenantId']
    AZURE_CLIENT_ID = data['clientId']
    AZURE_CLIENT_SECRET = data['clientSecret']

## Get Azure Key Vault parameters from the environment variables
# AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', '')
# AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID', '')
# AZURE_CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET', '')
# AZURE_KEYVAULT_NAME = os.environ.get('AZURE_KEYVAULT_NAME', '')

# Azure Key Vault URL
AZURE_KEYVAULT_URL = f"https://{AZURE_KEYVAULT_NAME}.vault.azure.net/"

# Import libraries
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

# Create a secret client
credential = ClientSecretCredential( AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
client = SecretClient(vault_url=AZURE_KEYVAULT_URL, credential=credential)

# client = ''

# Define the base directory of your project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Set the STATIC_ROOT setting
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

KUBE_MANAGER_URL = os.environ.get('KUBE_MANAGER_URL', 'http://192.168.56.3:31999')