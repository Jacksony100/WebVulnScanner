# scanner/utils.py
# Вспомогательные функции

import random
import string
import requests
from urllib.parse import urljoin

from .payloads import HEADERS


def rand_tag(k: int = 6) -> str:
    """Генерирует случайную строку из букв для использования в качестве тега"""
    return ''.join(random.choices(string.ascii_lowercase, k=k))


# Список файлов и сигнатур для детекции CMS
CMS_FILES = {
    "WordPress": ["wp-login.php", "wp-links-opml.php", "license.txt", "wp-includes/version.php"],
    "Joomla": ["administrator/index.php", "joomla.xml", "language/en-GB/en-GB.xml"],
    "Drupal": ["core/CHANGELOG.txt", "modules/README.txt", "sites/default/settings.php"],
    "Magento": ["magento_version.php", "app/Mage.php", "skin/frontend/base/default/favicon.ico"]
}

CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla": ["Joomla!", "com_content"],
    "Drupal": ["Drupal.settings", "drupal.js"],
    "Magento": ["Mage.", "magento"]
}


def detect_cms(session: requests.Session, base_url: str) -> str | None:
    """Определяет CMS, используемую на сайте"""
    for cms, files in CMS_FILES.items():
        for f in files:
            try:
                r = session.get(urljoin(base_url, f), headers=HEADERS, timeout=5)
                if r.status_code == 200 and any(sig.lower() in r.text.lower() for sig in CMS_SIGNATURES[cms]):
                    return cms
            except Exception:
                pass
    # Эвристика на главной странице
    try:
        r = session.get(base_url, headers=HEADERS, timeout=5)
        for cms, sigs in CMS_SIGNATURES.items():
            if any(sig.lower() in r.text.lower() for sig in sigs):
                return cms
    except Exception:
        pass
    return None


def get_cms_version(session: requests.Session, base_url: str, cms: str) -> str | None:
    """Определяет версию CMS"""
    if cms == "WordPress":
        try:
            r = session.get(urljoin(base_url, "wp-includes/version.php"), headers=HEADERS, timeout=5)
            if r.ok:
                for line in r.text.splitlines():
                    if "$wp_version" in line:
                        return line.split("=")[1].strip(" ';")
        except Exception:
            pass
    elif cms == "Joomla":
        try:
            r = session.get(urljoin(base_url, "joomla.xml"), headers=HEADERS, timeout=5)
            if r.ok and "<version>" in r.text:
                from xml.etree import ElementTree
                root = ElementTree.fromstring(r.text)
                version = root.find(".//version")
                return version.text if version is not None else None
        except Exception:
            pass
    elif cms == "Drupal":
        try:
            r = session.get(urljoin(base_url, "core/CHANGELOG.txt"), headers=HEADERS, timeout=5)
            if r.ok:
                for line in r.text.splitlines():
                    if line.startswith("Drupal "):
                        return line.split()[1].strip(",")
        except Exception:
            pass
    elif cms == "Magento":
        try:
            r = session.get(urljoin(base_url, "magento_version.php"), headers=HEADERS, timeout=5)
            if r.ok and "Magento" in r.text:
                return r.text.split("Magento/")[1].split()[0]
        except Exception:
            pass
    return None