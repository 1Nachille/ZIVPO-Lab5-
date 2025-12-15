# ZIVPO-Lab5-
# Лабораторная работа 5


## DAST
Целевое приложение: `vulnerable_app.py` (Flask-приложение)

## Шаги развертывания:

**Создание виртуального окружения**

`python3 -m venv venv`

**Активация (Linux/Mac)**

`source venv/bin/activate`

<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/Снимок_экрана_2025-12-14_200911.jpg" width="800" height="600">




**Установка зависимостей**

pip install Flask==2.3.3 requests==2.31.0

<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/Снимок_экрана_2025-12-14_201118.jpg" width="800" height="600">

**Запуск приложения**

python vulnerable_app.py

Результат: Приложение успешно запущено и доступно по адресу http://localhost:5000.

<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/Снимок_экрана_2025-12-14_201825.jpg" width="800" height="600">


## Сканирование с использованием OWASP ZAP

Сначала запустили ZAPROXY из меню Kali Linux и создали новый контекст с целевым URL: http://localhost:5000, затем запустили автоматическое сканирование (сначала Spider + Actie scan)

<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/Снимок_экрана_2025-12-14_215329.jpg" width="800" height="600">

Затем выполнили фаззинг через интерфейс ZAP. Для этого выбрали запрос GET:search(q) в History. Выбрали параметр q и добавили payloads из файла

<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/Снимок_экрана_2025-12-14_215805.jpg" width="800" height="600">
<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/add_fuzz_file.jpg" width="800" height="600">

По итогу вот что получилось после полного сканирования инструментом Zaproxy

<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/Снимок_экрана_2025-12-14_223950.jpg" width="800" height="600">

## Сканирование с использованием Nikto

Для дополнительного анализа используем Nikto. 
```bash

sudo apt update
sudo apt install nikto
nikto -h http://localhost:5000 -0 nikto_otchet.html -Format html
```
В итоге получем вот такой отчет
<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/nitko_pro1.jpg" width="800" height="600">
<img src="https://github.com/1Nachille/ZIVPO-Lab5-/blob/main/images/nikto_pro2.jpg" width="800" height="600">

## ТРИАЖ УЯЗВИМОСТЕЙ

В рамках выполнения лабораторной работы был развернут уязвимый веб-приложение OWASP Juice Shop, доступное по адресу:

`http://localhost:3000`

Для динамического анализа и выявления уязвимостей использовался инструмент OWASP ZAP (Zed Attack Proxy)
Сканирование включало в себя:

* Spider-обход приложения;

* Активное сканирование выявленных точек входа;

* Фаззинг параметров HTTP-запросов.

По результатам анализа был сформирован отчёт OWASP ZAP, содержащий 12 различных типов уязвимостей с уровнями риска от Informational до High.

Выбор уязвимостей для триажа

Для проведения триажа были отобраны следующие уязвимости из отчёта OWASP ZAP:

* SQL Injection (SQLite) — уровень риска High

* Content Security Policy (CSP) Header Not Set — уровень риска Medium

* Session ID in URL Rewrite — уровень риска Medium

* Cross-Domain Misconfiguration — уровень риска Medium

* Timestamp Disclosure (Unix) — уровень риска Low
