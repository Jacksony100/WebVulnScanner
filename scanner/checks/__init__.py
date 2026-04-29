from .base import BaseCheck, ActiveCheck, PassiveCheck
from .headers import SecurityHeadersCheck
from .xss import ReflectedXSSCheck
from .sqli import SQLInjectionCheck
from .ssti import SSTICheck
from .open_redirect import OpenRedirectCheck
from .crlf import CRLFCheck
from .exposure import ExposureCheck
from .source_maps import SourceMapCheck
from .cors import CORSCheck
from .jwt import JWTCheck
from .idor import PotentialIDORCheck
from .graphql import GraphQLCheck
from .openapi import OpenAPIDocsCheck


def default_checks():
    return [
        SecurityHeadersCheck(),
        OpenAPIDocsCheck(),
        JWTCheck(),
        SourceMapCheck(),
        ExposureCheck(),
        CORSCheck(),
        GraphQLCheck(),
        ReflectedXSSCheck(),
        SQLInjectionCheck(),
        SSTICheck(),
        OpenRedirectCheck(),
        CRLFCheck(),
        PotentialIDORCheck(),
    ]


__all__ = [
    "BaseCheck",
    "ActiveCheck",
    "PassiveCheck",
    "default_checks",
]
