from .uvicorn_logs import UvicornLogPattern
from .ipv4 import IPv4Pattern
from .emails import EmailPattern
from .urls import URLPattern
from .hashes import HashPattern
from .aws_keys import AWSKeyPattern
from .base64 import Base64Pattern
from .jwt import JWTPattern

ALL_PATTERNS = [IPv4Pattern, EmailPattern, URLPattern, HashPattern, AWSKeyPattern, Base64Pattern, JWTPattern]
