<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-%20Web%20Scanner-orange?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/Docker-ready-blue?logo=docker" alt="Docker ready">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/github/repo-size/Jacksony100/Web-vuln-scanner" alt="Repo size">
</p>

# 🔒 Advanced Web Vulnerability Scanner 5.1

# Скриншот UI
<img src="screenshots/ui.jpg" alt="UI screenshot" width="600">

# Пример отчета
<img src="screenshots/report.jpg" alt="Report screenshot" width="600">

**Интерактивный сканер уязвимостей** для веб-приложений с поддержкой SSRF, SQLi, XSS, CSRF, IDOR и других векторных атак.

---

## 🚀 Возможности

- 🛠️ Расширенное обнаружение:
  - XSS (Reflected, Stored, DOM)
  - SQL Injection (bool, blind, time-based)
  - OS Command Injection, SSRF, IDOR
  - CSRF (token detection), Path Traversal
- 🌐 Интерфейс:
  - Веб-панель с графиками (Chart.js)
  - Светлая/тёмная тема
  - Фильтрация и экспорт отчётов в **HTML/PDF**
- 🐳 Поддержка Docker
- 🧠 Обнаружение CMS (WordPress, Joomla, Drupal)

---

## 📦 Установка

```bash
git clone https://github.com/Jacksony100/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
python app.py
