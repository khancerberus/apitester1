from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from rest_framework import viewsets
from rest_framework import permissions
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from appTest.serializers import UserSerializer

import requests
import json

#LOGIN
@api_view(['POST'])
def login(request):
    username = request.POST.get('username')
    password = request.POST.get('password')

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response("Usuario inválido")

    pwd_valid = check_password(password, user.password)

    if not pwd_valid:
        Response('Contraseña inválida')

    token, _ = Token.objects.get_or_create(user=user)

    return Response(token.key)

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    response = requests.get("https://jsonplaceholder.typicode.com/todos/1").text
    resource = json.loads(response)
    print("Titulo" + resource['title'])
