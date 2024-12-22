from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .models import User, UserProfile
from django.contrib.auth.password_validation import validate_password
import requests
from django.contrib.auth import get_user_model

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'email', 'phone', 'password', 'confirm_password', 'number_card', 'gender']
        extra_kwargs = {'password': {'write_only': True}}


    def to_representation(self, instance):
        data = super(UserSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data

########################  eskiz sms ################################

    def create(self,  validated_data):
        user = super(UserSerializer, self).create(validated_data)
        if user.phone:
            code = user.create_verify_code()
        url = "http://notify.eskiz.uz/api/auth/login"

        payload = {'email': 'imronhoja336@mail.ru',
                  'password': 'ombeUIUC8szPawGi3TXgCjDXDD0uAIx2AmwLlX9M'}
        files = [

        ]
        headers = {
            # 'Authorization': f"{Bearer}"
        }

        response = requests.request("POST", url, headers=headers, data=payload, files=files)

        token1 = response.json()["data"]["token"]

        url = "http://notify.eskiz.uz/api/message/sms/send"

        payload = {'mobile_phone': str(user.phone),
                  'message': f"Envoy ilovasiga ro‘yxatdan o‘tish uchun tasdiqlash kodi: {code}",
                  'from': '4546',
                  'callback_url': 'http://0000.uz/test.php'}
        files = [

        ]

        headers = {
            'Authorization': f"Bearer {token1}"
        }

        response = requests.request("POST", url, headers=headers, data=payload, files=files)


        print(response.text)
        print(code)
        user.save()
        return user

    def validate(self, attrs):
        password = attrs.get("password")
        confirm_password = attrs.get('confirm_password')
        if password != confirm_password:
            raise ValidationError("Parollar bir-biriga mos emas!")
        return attrs
        print(attrs)



     ####################### EDIT PROFILE ###################

class ChangeUserInformation(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'confirm_password']

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password !=confirm_password:
            raise ValidationError(
                {
                    "message": "Parolingiz va tasdiqlash parolingiz bir-biriga teng emas"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError(
                {
                    "message": "Foydalanuvchi nomi 5 dan 30 gacha belgidan iborat bo'lishi kerak"
                }
            )
        if username.isdigit():
            raise ValidationError(
                {
                    "message": "Ushbu foydalanuvchi nomi butunlay raqamli"
                }
            )
        return username

    def update(self, instance, validated_data):

        instance.password = validated_data.get('password', instance.password)
        instance.username = validated_data.get('username', instance.username)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))

        instance.save()
        return instance


    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['phone', 'password', 'confirm_password']



##################### reset-password ##########################

class PhoneSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)

class CodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=4)

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=128)
    confirm_password = serializers.CharField(max_length=128)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data