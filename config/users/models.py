import random
from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken


class User(AbstractUser):
    full_name = models.CharField(max_length=50, unique=True)
    phone = models.CharField(max_length=15, unique=True, help_text="+998950701662")
    number_card = models.CharField(max_length=16, unique=True, null=True, blank=True)
    email = models.EmailField(max_length=100, unique=True, null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female')])
    confirm_password = models.CharField(max_length=128, default=False)
    code = models.CharField(max_length=4, null=True, blank=True)
    is_confirmed = models.BooleanField(default=False)

    def create_verify_code(self):
        # Telefon raqamidan foydalanib tasdiqlash kodi yaratish
        code = "".join([str(random.randint(0, 10000) % 10) for _ in range(4)])
        self.code = code  # User modelidagi `code` maydoniga yozish
        self.save()  # Yangi kodni saqlash
        return code

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def save(self, *args, **kwargs):
        self.clean()
        super(User, self).save(*args, **kwargs)

    def clean(self):
        self.hashing_password()

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['username', 'full_name', 'email', 'number_card', 'gender']

    def __str__(self):
        return self.phone


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=13, unique=True, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.user.name