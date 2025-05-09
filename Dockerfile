# Используем официальный образ Python 3.11-slim для минимизации размера
FROM python:3.11-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем requirements.txt и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект в рабочую директорию
COPY . .

# Указываем порт, который будет использоваться приложением
EXPOSE 5000

# Команда для запуска приложения
CMD ["python", "app.py"]