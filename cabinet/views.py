from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.tokens import default_token_generator as token_generator

from django.core.exceptions import ValidationError
from django.http import HttpResponseBadRequest

from django.utils.http import urlsafe_base64_decode

from django.urls import reverse_lazy
from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView
from django.views import View

from .forms import MyUserCreationForm, MyAuthenticationForm
from .utils import send_email_for_verify
from .models import *

User = get_user_model()


class Register(View):
    """
    Представление для регистрации новых пользователей.

    Это представление отображает форму регистрации новых пользователей и обрабатывает POST-запросы для создания новых учетных записей.
    """
    template_name = 'cabinet/register.html'

    def get(self, request):
        """Отображает форму регистрации нового пользователя."""
        context = {
            'form': MyUserCreationForm()
        }
        return render(request, self.template_name, context)

    def post(self, request):
        """ Обрабатывает POST-запросы для создания новых учетных записей."""
        form = MyUserCreationForm(request.POST)

        if form.is_valid():
            form.save()
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')
            user = authenticate(email=email, password=password)
            send_email_for_verify(request, user)
            return redirect('confirm_email')
        context = {
            'form': form
        }
        return render(request, self.template_name, context)


class EmailVerify(View):
    """Представление для подтверждения адреса электронной почты пользователя."""
    def get(self, request, uidb64, token):
        """ Обрабатывает GET-запросы для подтверждения адреса электронной почты пользователя."""
        user = self.get_user(uidb64)
        if user is not None and token_generator.check_token(user, token):
            user.email_verify = True
            user.save()
            login(request, user)
            return redirect('home')
        return redirect('invalid_verify')

    @staticmethod
    def get_user(uidb64):
        """Получает пользователя по base64-кодированному идентификатору пользователя (uidb64) из запроса."""
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError,
                User.DoesNotExist, ValidationError):
            user = None
        return user


class SignInView(LoginView):
    """ Класс представления для авторизации пользователей."""
    form_class = MyAuthenticationForm
    template_name = 'cabinet/login.html'
    success_url = reverse_lazy('news')

    def get_context_data(self, **kwargs):
        """ Метод для получения контекстных данных. Добавляет форму авторизации в контекст."""
        context = super().get_context_data(**kwargs)
        context['login_form'] = self.get_form(self.form_class)
        return context

    def get_success_url(self):
        """Метод для получения URL-адреса, на который будет перенаправлен пользователь после успешной авторизации."""
        return reverse_lazy('home')


class AuthLogoutView(LogoutView):
    """ Класс представления для выхода пользователя из системы (логаута)."""
    template_name = 'home.html'


class UserListView(ListView):
    """Представление для отображения списка объектов CustomUser."""
    model = CustomUser
    template_name = 'cabinet/users_list.html'
    context_object_name = 'users'

    def get_queryset(self):
        return CustomUser.objects.all()


class EditProfileView(View):
    """Представление для отображения страницы редактирования профиля."""
    template_name = 'cabinet/edit_profile.html'


class UserProfileView(View):
    """Представление для отображения страницы профиля."""
    template_name = 'cabinet/user_page.html'  # Укажите имя вашего шаблона

    def get(self, request, pk, **kwargs):
        user = get_object_or_404(CustomUser, pk=pk)
        return render(request, self.template_name, {'user': user})


class ChangeEmailView(View):
    """Представление для изменения емэйла"""
    template_name = 'cabinet/change_email.html'

    def get(self, request):
        return render(request, self.template_name)  # Отправляем шаблон формы

    def post(self, request):        # Получаем данные из POST-запроса
        new_email = request.POST.get('new_email')

        if CustomUser.objects.filter(email=new_email).exists():
            return HttpResponseBadRequest("Пользователь с этим email уже существует.")

        user = request.user
        user.email = new_email
        user.save()
        return redirect('home')  # Перенаправление на страницу успеха
