from django.db import models
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)


class UserManger(BaseUserManager):
    """
    Создание CustomUser.
    Для этого CustomUser должен быть унаследован от  BaseUserManager.
    """

    def create_user(self, username, email, password=None):
        """
        Создание и возвращение CustomUser с email, password, username.
        """

        if username is None:
            raise TypeError("WARNING! Users must have a username.")

        if email is None:
            raise TypeError("WARNING! Users must have a email.")

        user = self.model(username=username, email=self.normalize_email(email))  # Нормализация email
        user.set_password(password)  # Установка password
        user.save()  # Схранение CustomUser

        return user

    def create_superuser(self, username, email, password):
        """ Создание и возвращение пользователя с привилегиями суперадмина. """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(username, email, password)
        user.is_superuser = True  # Определяет, что пользователь имеет все права без явного их присвоения пользователю.
        user.is_staff = True  # Установка доступа к интерфейсу администратора
        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """
    Уникальный идентификатор пользователя, понятный пользователям, для представления CustomUser в пользовательском
    интерфейсе.
    db_index проиндексирует username в DB для повышения скорости поиска
    обычно СУБД индексирует primary key но в Django усть возможность индексировать другие поля
    """
    username = models.CharField(db_index=True, max_length=255, unique=True)

    """
    Укзывается Unique = True для проверки данных в модели. Если User решит сохранить повторное значение
    в поле с Unique то будет вызвана ошибка. В данном поле db_index=True явно указывать не нужно т.к.
    Unique=True автоматически индексирует данное поле.
    """
    email = models.EmailField(unique=True)

    """
    Данное поле для того, что бы при удаление пользователем своего профиля, он не удалил его а деактивировал его, 
    в таком случае профиль не будет отображаться в приложении. И данные остануться в DB.
    """
    is_active = models.BooleanField(default=True)

    """
    Флаг который устанавливается для определения того, какие Users могут войти в административную часть приложения
    для большинства Users будет False.
    """
    is_staff = models.BooleanField(default=False)

    """Временная метка создания объекта."""
    created_at = models.DateTimeField(auto_now_add=True)

    """Временная метка последнего обновления объекта."""
    update_at = models.DateTimeField(auto_now=True)

    """Свойство USERNAME_FIELD показывает какое поле будет использоваться для входа в систему."""
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    """Сообщает Django, что определенный выше класс UserManager должен управлять объектами этого типа."""
    object = UserManger()

    @property
    def token(self):
        """
        Позволяет получить токен пользователя путем вызова user.token, вместо
        user._generate_jwt_token(). Декоратор @property выше делает это
        возможным. token называется "динамическим свойством".
        """
        return self._generate_jwt_token()

    def get_full_name(self):
        """
        Этот метод требуется Django для таких вещей, как обработка электронной
        почты. Обычно это имя фамилия пользователя, но поскольку мы не
        используем их, будем возвращать username.
        """
        return self.username

    def get_short_name(self):
        """ Аналогично методу get_full_name(). """
        return self.username

    def _generate_jwt_token(self):
        """
        Генерирует веб-токен JSON, в котором хранится идентификатор этого
        пользователя, срок действия токена составляет 1 день от создания
        """
        dt = datetime.now() + timedelta(days=1)

        token = jwt.encode({
            'id': self.pk,
            'exp': int(dt.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS256')

        return token

    def __str__(self):
        """Строковое представление модели User"""
        return f"{self.email}"
