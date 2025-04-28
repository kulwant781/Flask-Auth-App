import os

class Config:
    SECRET_KEY = "your_secret_key"
    MYSQL_HOST = "localhost"
    MYSQL_USER = "root"
    MYSQL_PASSWORD = "admin"
    PORT = 3306
    MYSQL_DB = "flask_auth_db"
    API_KEY = ""  # Replace with your actual API key
    BASE_URL = "https://newsapi.org/v2/everything"
