from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _


class CustomUser(AbstractUser):
    """
    Пользовательская модель пользователя с дополнительным полем "Email".

    Эта модель расширяет стандартную модель пользователя (AbstractUser), добавляя поле "Email" и флаг подтверждения
    адреса электронной почты.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(
        _('email address'),
        unique=True,
    )

    email_verify = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
