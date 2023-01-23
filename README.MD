# Script for collecting information about the network perimeter

## General information
The script takes a list of domain names as input and outputs a csv file with the following fields:

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

That is, the list of domain names is converted into a convenient table that includes additional information.
This can be useful for assessing the overall picture of the infrastructure/server placement.

The script generates files `./output/nmap_ipv4_targets.txt` and `./output/nmap_ipv6_targets.txt`
with a list of IP addresses for subsequent scanning, such as nmap.

Also, the script generates `./output/nmap_networks_v4.txt` with a list of subnets.

## Requirements

You need to register on the services https://ipregistry.co/ and https://apilayer.com to get the API keys.

https://ipregistry.co/ provides information on IP, 100,000 requests are available for free.

https://apilayer.com is needed to obtain whois data, free limit - 3000 requests per month.

The list of domain names should be placed in the ./input directory in one or more txt files.

One domain name per line.

## Build

    docker build . -t 'scope_csv_report'

## Run

    docker run --rm \
      -t \
      -e X_IPREGISTRY_KEY=__API_KEY__ \
      -e X_APILAYER_KEY=__API_KEY__ \
      -v "$PWD"/input:/opt/input \
      -v "$PWD"/output:/opt/output \
      scope_csv_report

---

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

Скрипт формирует файлы `./output/nmap_ipv4_targets.txt` и `./output/nmap_ipv6_targets.txt` со списком IP адресов для последующего сканирования, например, nmap.

А также `./output/nmap_networks_v4.txt` со списоком подсетей.

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
