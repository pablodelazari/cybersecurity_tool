import re
import socket
from typing import Optional, List, Dict, Any
import requests
from urllib.parse import urlparse

def is_valid_ip(ip: str) -> bool:
    """Verifica se um endereço IP é válido."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_domain(domain: str) -> bool:
    """Verifica se um domínio é válido."""
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$'
    )
    return bool(pattern.match(domain))

def get_domain_info(target: str) -> Dict[str, Any]:
    """Obtém informações sobre um domínio."""
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = None
            
        return {
            "ip": ip,
            "hostname": hostname,
            "is_ip": is_valid_ip(target),
            "is_domain": is_valid_domain(target)
        }
    except socket.gaierror:
        return {
            "error": "Não foi possível resolver o domínio/IP",
            "is_ip": is_valid_ip(target),
            "is_domain": is_valid_domain(target)
        }

def get_http_info(url: str) -> Dict[str, Any]:
    """Obtém informações sobre um servidor HTTP."""
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
        
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "redirects": [r.url for r in response.history],
            "final_url": response.url
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def normalize_url(url: str) -> str:
    """Normaliza uma URL para um formato padrão."""
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def extract_domain(url: str) -> str:
    """Extrai o domínio principal de uma URL."""
    parsed = urlparse(url)
    return parsed.netloc

def format_port_description(port: int) -> str:
    """Retorna uma descrição para portas comuns."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP Alternativo",
        8443: "HTTPS Alternativo"
    }
    return common_ports.get(port, "Serviço Desconhecido")

def create_error_report(error: Exception, context: str) -> Dict[str, str]:
    """Cria um relatório de erro formatado."""
    return {
        "error_type": type(error).__name__,
        "error_message": str(error),
        "context": context,
        "suggestions": get_error_suggestions(error)
    }

def get_error_suggestions(error: Exception) -> List[str]:
    """Retorna sugestões baseadas no tipo de erro."""
    suggestions = {
        "ConnectionRefusedError": [
            "Verifique se o serviço está em execução",
            "Verifique se a porta está correta",
            "Verifique se há firewalls bloqueando a conexão"
        ],
        "TimeoutError": [
            "Verifique sua conexão com a internet",
            "O servidor pode estar sobrecarregado",
            "Tente aumentar o timeout da conexão"
        ],
        "gaierror": [
            "Verifique se o domínio está correto",
            "Verifique se há problemas com o DNS",
            "O servidor pode estar offline"
        ]
    }
    return suggestions.get(type(error).__name__, ["Erro não específico, verifique os logs para mais detalhes"])