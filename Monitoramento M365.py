#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import re
import ssl
import requests
import geoip2.database
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo  # Python 3.9+
from dotenv import load_dotenv
from ldap3 import Server, Connection, Tls, ALL, SUBTREE
from azure.communication.email import EmailClient

# ========== CONFIGS ==========
load_dotenv('/var/ossec/active-response/bin/.env')

OPENSEARCH_URL = os.getenv('OPENSEARCH_URL')
OPENSEARCH_USER = os.getenv('OPENSEARCH_USER')
OPENSEARCH_PASS = os.getenv('OPENSEARCH_PASS')
INDEX_PATTERN = "wazuh-alerts-*"

LOG_DIR = '/var/ossec/active-response/logs'
CACHE_FILE = f"{LOG_DIR}/o365_ip_cache.json"
LAST_RUN_FILE = f"{LOG_DIR}/o365_last_run.txt"
LOG_FILE = f"{LOG_DIR}/monitor_o365_log.txt"

ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')
AZURE_CONNECTION_STRING = os.getenv('AZURE_CONNECTION_STRING')
AZURE_EMAIL_FROM = os.getenv('AZURE_EMAIL_FROM')
AZURE_EMAIL_TO = os.getenv('AZURE_EMAIL_TO')
GEOIP_DB = '/var/ossec/active-response/bin/GeoLite2-Country.mmdb'
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
CACHE_TTL = 540  # 9 minutos

# Configs AD/LDAPS
AD_BASEDN   = os.getenv("AD_BASE_DN")
AD_USER     = os.getenv("AD_BIND_USER")
AD_PASS     = os.getenv("AD_BIND_PASS")
AD_PORT     = int(os.getenv("AD_LDAPS_PORT", "636"))
AD_HOSTS    = [h.strip() for h in os.getenv("AD_LDAPS_HOSTS", "").split(",") if h.strip()]
AD_CA_FILE  = os.getenv("AD_CA_FILE")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# Timezone Brasil
TZ_BR = ZoneInfo("America/Sao_Paulo")

# Lista de e-mails considerados "vazados"
USERS_ALWAYS_ALERT = [
    
]


def log(msg):
    br_time = datetime.now(TZ_BR).isoformat()
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{br_time}] {msg}\n")
    print(f"[{br_time}] {msg}")


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)


def load_last_run():
    if os.path.exists(LAST_RUN_FILE):
        with open(LAST_RUN_FILE) as f:
            return f.read().strip()
    return (datetime.utcnow() - timedelta(minutes=20)).replace(microsecond=0).isoformat() + "Z"


def save_last_run(iso_time):
    with open(LAST_RUN_FILE, 'w') as f:
        f.write(iso_time)


def abuse_lookup(ip):
    headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        r = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=10)
        data = r.json().get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        country_code = data.get('countryCode', '')
        return score, country_code
    except Exception as e:
        log(f"Erro consulta AbuseIPDB: {e}")
        return 0, ""


def get_country(ip):
    try:
        reader = geoip2.database.Reader(GEOIP_DB)
        response = reader.country(ip)
        return response.country.name or ""
    except Exception:
        return ""


def virustotal_lookup(ip):
    """Consulta reputação do IP na VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"malicious": "?", "suspicious": "?", "harmless": "?", "link": ""}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            log(f"VirusTotal resposta {r.status_code}: {r.text[:100]}")
            return {
                "malicious": "?",
                "suspicious": "?",
                "harmless": "?",
                "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
            }
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
    except Exception as e:
        log(f"Erro consulta VirusTotal: {e}")
        return {
            "malicious": "?",
            "suspicious": "?",
            "harmless": "?",
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }


# ===== Helpers de AD (UAC) =====
def decode_uac(uac: int) -> str:
    """Converte userAccountControl em texto amigável (parecido com seu PowerShell)."""
    UF_ACCOUNTDISABLE     = 0x0002
    UF_DONT_EXPIRE_PASSWD = 0x10000

    if uac & UF_ACCOUNTDISABLE:
        return "Conta desabilitada, sem expiração de senha." if (uac & UF_DONT_EXPIRE_PASSWD) else "Conta desabilitada."
    else:
        return "Conta habilitada, sem expiração de senha." if (uac & UF_DONT_EXPIRE_PASSWD) else "Conta habilitada."


def is_account_enabled(uac: int) -> bool:
    """True se a conta estiver habilitada (bit de desabilitada NÃO setado)."""
    UF_ACCOUNTDISABLE = 0x0002
    return (uac & UF_ACCOUNTDISABLE) == 0


def ad_lookup_email_via_ldaps(email: str, timeout=6):
    """
    Consulta o AD via LDAPS por e-mail (mail ou proxyAddresses).
    Retorna: {found, email, name, uac, status}
    """
    try:
        if not email or not EMAIL_REGEX.match(email):
            return {"found": False, "email": email, "name": None, "uac": None, "status": "EMAIL_INVALIDO"}

        if not AD_HOSTS:
            return {"found": False, "email": email, "name": None, "uac": None, "status": "NO_AD_HOSTS"}

        if not AD_BASEDN:
            return {"found": False, "email": email, "name": None, "uac": None, "status": "NO_BASE_DN"}

        if not AD_CA_FILE or not os.path.isfile(AD_CA_FILE):
            return {
                "found": False,
                "email": email,
                "name": None,
                "uac": None,
                "status": f"ERRO_CA_INEXISTENTE: {AD_CA_FILE}"
            }

        last_err = None

        for host in AD_HOSTS:
            try:
                tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=AD_CA_FILE)
                server = Server(host, port=AD_PORT, use_ssl=True, get_info=ALL, tls=tls)

                with Connection(
                    server,
                    user=AD_USER,
                    password=AD_PASS,
                    auto_bind=True,
                    receive_timeout=timeout
                ) as conn:

                    ldap_filter = f"(|(mail={email})(proxyAddresses=SMTP:{email.upper()}))"
                    attrs = ["displayName", "userAccountControl", "mail", "proxyAddresses"]

                    ok = conn.search(
                        AD_BASEDN,
                        ldap_filter,
                        SUBTREE,
                        attributes=attrs
                    )

                    if not ok or not conn.entries:
                        return {
                            "found": False,
                            "email": email,
                            "name": None,
                            "uac": None,
                            "status": "NAO_ENCONTRADO"
                        }

                    entry = conn.entries[0]
                    uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
                    name = str(entry.displayName.value) if entry.displayName else None
                    status = decode_uac(uac)

                    return {
                        "found": True,
                        "email": email,
                        "name": name,
                        "uac": uac,
                        "status": status
                    }

            except Exception as e:
                last_err = e
                continue

        return {
            "found": False,
            "email": email,
            "name": None,
            "uac": None,
            "status": f"ERRO_AD_ALL_HOSTS_TLS: {last_err}"
        }

    except Exception as e:
        return {"found": False, "email": email, "name": None, "uac": None, "status": f"ERRO_AD: {e}"}


def montar_corpo_email(alertas):
    if not alertas:
        return "", ""

    # ===== Texto plano (simples / para fallback) =====
    plain = "Atividade Externa no Office 365\n\n"
    for a in alertas:
        plain += (
            f"Usuário.............: {a['user']}\n"
            f"Nome (AD)...........: {a.get('ad_name')}\n"
            f"Status AD...........: {a.get('ad_status')} (UAC={a.get('ad_uac')})\n"
            f"E-mail vazado.......: {'Sim' if a.get('email_vazado') else 'Não'}\n"
            f"IP / País...........: {a['ip']} / {a['abuse_country']}\n"
            f"Horário (BR)........: {a['timestamp_br']}\n"
            f"Operação............: {a['operation']}\n"
            f"Score AbuseIPDB.....: {a['abuse_score']}\n"
            f"VirusTotal..........: Malicious={a['vt_malicious']}, "
            f"Suspicious={a['vt_suspicious']}, Harmless={a['vt_harmless']}\n"
            f"AbuseIPDB...........: https://www.abuseipdb.com/check/{a['ip']}\n"
            f"VirusTotal..........: {a['vt_link']}\n"
            f"Motivo..............: {a['reason']}\n"
            "-------------------------\n"
        )

    # ===== HTML compacto: tabela reduzida + detalhes =====
    html = """
    <html>
    <head>
      <meta charset="utf-8" />
      <style>
        body {
          font-family: Arial, sans-serif;
          color: #222;
          font-size: 13px;
        }
        .title {
          font-size: 18px;
          font-weight: bold;
          margin-bottom: 4px;
        }
        .subtitle {
          font-size: 13px;
          color: #555;
          margin-bottom: 12px;
        }
        table {
          border-collapse: collapse;
          width: 100%;
          margin-top: 8px;
          margin-bottom: 4px;
        }
        th, td {
          border: 1px solid #e0e0e0;
          padding: 6px 8px;
          text-align: left;
        }
        th {
          background: #f4f4f4;
          font-weight: bold;
        }
        .card {
          border: 1px solid #ddd;
          border-radius: 4px;
          padding: 6px 8px;
          margin-bottom: 10px;
          background: #fafafa;
        }
        .details {
          font-size: 12px;
          color: #444;
          line-height: 1.4;
        }
        .details strong {
          font-weight: bold;
        }
        .motivo {
          font-weight: bold;
          color: #c0392b;
        }
        a {
          color: #1976d2;
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="title">Atividade Externa no Office 365 Monitorada</div>
      <div class="subtitle">
        Login fora do Brasil com conta habilitada no AD e verificação de reputação AbuseIPDB / VirusTotal.
      </div>
    """

    for a in alertas:
        email_vazado = a.get('email_vazado')
        html += f"""
        <div class="card">
          <table>
            <tr>
              <th>Usuário</th>
              <th>Status AD</th>
              <th>IP</th>
              <th>País</th>
              <th>Score AbuseIPDB</th>
              <th>Motivo</th>
            </tr>
            <tr>
              <td>{a['user']}</td>
              <td>{a.get('ad_status')}</td>
              <td>{a['ip']}</td>
              <td>{a['abuse_country']}</td>
              <td>{a['abuse_score']}</td>
              <td class="motivo">{a['reason']}</td>
            </tr>
          </table>
          <div class="details">
            <strong>Nome (AD):</strong> {a.get('ad_name')}<br/>
            <strong>UAC:</strong> {a.get('ad_uac')}<br/>
            <strong>E-mail em lista de vazamento:</strong> {"Sim" if email_vazado else "Não"}<br/>
            <strong>Operação:</strong> {a['operation']}<br/>
            <strong>Horário (BR):</strong> {a['timestamp_br']}<br/>
            <strong>VirusTotal:</strong>
              Malicious={a['vt_malicious']} |
              Suspicious={a['vt_suspicious']} |
              Harmless={a['vt_harmless']}<br/>
            <strong>AbuseIPDB:</strong>
              <a href="https://www.abuseipdb.com/check/{a['ip']}" target="_blank">
                Ver IP no AbuseIPDB
              </a><br/>
            <strong>VirusTotal:</strong>
              <a href="{a['vt_link']}" target="_blank">
                Ver IP no VirusTotal
              </a>
          </div>
        </div>
        """

    html += """
    </body>
    </html>
    """
    return plain, html


def enviar_email(alertas):
    if not alertas:
        return
    subject = f'Notificação Wazuh x M365 | {len(alertas)} IP(s) - Análise Recomendada'
    body, html_body = montar_corpo_email(alertas)
    try:
        email_client = EmailClient.from_connection_string(AZURE_CONNECTION_STRING)
        recipients_list = [{"address": addr.strip()} for addr in AZURE_EMAIL_TO.split(",")]
        message = {
            "senderAddress": AZURE_EMAIL_FROM,
            "recipients": {"to": recipients_list},
            "content": {
                "subject": subject,
                "plainText": body,
                "html": html_body
            }
        }
        poller = email_client.begin_send(message)
        result = poller.result()
        log(f"E-mail enviado, status: {result['status']}")
    except Exception as e:
        log(f"Erro envio email: {e}")


def main():
    cache = load_cache()
    last_run = load_last_run()
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    save_last_run(now)
    log(f"Janela de busca: gte={last_run}, lte={now}")

    url = f"{OPENSEARCH_URL}/{INDEX_PATTERN}/_search"
    query = {
        "size": 1000,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": last_run, "lte": now}}},
                    {"match": {"data.integration": "office365"}},
                    {"terms": {"data.office365.Operation": ["UserLoginFailed", "UserLoggedIn"]}}
                ]
            }
        }
    }

    try:
        resp = requests.post(
            url,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False,
            timeout=60
        )
        log(f"OpenSearch resp: {resp.status_code} {resp.text[:500]}")
        if resp.status_code != 200:
            log(f"Erro OpenSearch: {resp.text}")
            return

        hits = resp.json()['hits']['hits']
        log(f"{len(hits)} eventos retornados do OpenSearch.")

        enviados = []
        ignorados = 0

        for hit in hits:
            event = hit['_source']
            office365 = event.get('data', {}).get('office365', {})
            ip = office365.get('ActorIpAddress') or office365.get('ClientIP')
            user = office365.get('UserId') or office365.get('TargetUserOrPrincipalName') or office365.get('UserKey')
            op = office365.get('Operation') or office365.get('ActionType')
            ts = event.get('@timestamp')

            if not (ip and user and op):
                ignorados += 1
                log(f"Evento ignorado (campo ausente): {json.dumps(event, indent=2)}")
                continue

            key = f"{ip}_{user}_{op}"
            if key in cache and (time.time() - cache[key]) < CACHE_TTL:
                continue

            geoip_country = get_country(ip)
            user_lower = user.lower() if user else ""

            # Apenas IPs fora do Brasil
            if geoip_country != "":
                abuse_score, abuse_country = abuse_lookup(ip)

                # Consulta AD para o usuário
                ad_info   = ad_lookup_email_via_ldaps(user)
                ad_found  = ad_info.get("found")
                ad_uac    = ad_info.get("uac")
                ad_status = ad_info.get("status")
                ad_name   = ad_info.get("name")

                # Conta habilitada no AD
                ad_enabled = bool(ad_found) and ad_uac is not None and is_account_enabled(int(ad_uac))

                # E-mail está na lista de vazamento?
                email_vazado = user_lower in [u.lower() for u in USERS_ALWAYS_ALERT]

                # ========== REGRA DE CASO DE USO ==========
                # - Login sucesso/falho (filtrado na query)
                # - IP fora do Brasil
                # - Conta habilitada no AD
                # - Score AbuseIPDB >= 0
                if not (ad_enabled and abuse_score >= 0):
                    cache[key] = time.time()
                    continue

                if email_vazado:
                    reason = "E-mail em lista de vazamento e conta habilitada fora do Brasil (AbuseIPDB >= 0)"
                else:
                    reason = "Conta habilitada fora do Brasil (AbuseIPDB >= 0)"

                # Converte timestamp para BR
                try:
                    dt_utc = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    timestamp_br = dt_utc.astimezone(TZ_BR).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp_br = ts

                # Lookup VirusTotal
                vt_data = virustotal_lookup(ip)
                alerta = {
                    "ip": ip,
                    "user": user,
                    "operation": op,
                    "abuse_score": abuse_score,
                    "abuse_country": abuse_country,  # sigla país
                    "timestamp_br": timestamp_br,
                    "timestamp": ts,
                    "vt_malicious": vt_data.get("malicious", "?"),
                    "vt_suspicious": vt_data.get("suspicious", "?"),
                    "vt_harmless": vt_data.get("harmless", "?"),
                    "vt_link": vt_data.get("link", ""),
                    "reason": reason,
                    "ad_found": ad_found,
                    "ad_status": ad_status,
                    "ad_name": ad_name,
                    "ad_uac": ad_uac,
                    "email_vazado": email_vazado,
                }
                enviados.append(alerta)
                log(f"Alerta preparado: {json.dumps(alerta)}")

            cache[key] = time.time()

        save_cache(cache)
        log(f"Eventos processados: {len(hits)}, ignorados: {ignorados}, enviados: {len(enviados)}")
        enviar_email(enviados)
    except Exception as e:
        log(f"Erro geral: {e}")


if __name__ == "__main__":
    main()
