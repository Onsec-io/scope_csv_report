# Скрипт для сбора информации о сетевом периметре

## Общая информация

На вход скрипт принимает список доменных имен, на выходе получается csv файл со следующими полями:
- ASN
- IP
- PTR
- NETWORK
- PROVIDER
- COUNTRY
- IP_TYPE
- L2_DOMAIN
- REGISTRAR
- DOMAIN_ORG
- DOMAIN

Т.е. список доменных имен превращается в удобную таблицу, включающую доп. информацию.
Это может быть полезно для оценки общей картины по инфраструктуре/размещению серверов.

Также скрипт формирует файлы `./output/nmap_ipv4_targets.txt` и `./output/nmap_ipv6_targets.txt` со списком IP адресов для последующего сканирования, например, nmap.

## Требования

Необходимо зарегистрироваться на сервисах https://ipregistry.co/ и https://apilayer.com для получения ключей API.

https://ipregistry.co/ предоставляет информацию по IP, бесплатно доступно 100.000 запросов.

https://apilayer.com нужен для получения whois данных, бесплатный лимит - 3000 запросов в месяц.

Список доменных имен нужно поместить в директорию ./input в один или несколько txt файлов.

По одному доменному имени на строку.

## Сбока

    docker build . -t 'scope_csv_report'

## Запуск

    docker run --rm \
      -t \
      -e X_IPREGISTRY_KEY=__API_KEY__ \
      -e X_APILAYER_KEY=__API_KEY__ \
      -v "$PWD"/input:/opt/input \
      -v "$PWD"/output:/opt/output \
      scope_csv_report
