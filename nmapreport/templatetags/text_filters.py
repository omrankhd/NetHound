from django import template
from django.template.defaultfilters import stringfilter
import re

register = template.Library()

@register.filter
@stringfilter
def splitlines(value):
    if value:
        return value.splitlines()
    return []

@register.filter
@stringfilter
def split(value, arg):
    if value:
        return value.split(arg)
    return []

@register.filter
@stringfilter
def extract_http_status(value):
    """Extract and format HTTP status line"""
    match = re.search(r'HTTP/[\d.]+ \d{3}.*', value)
    return match.group(0) if match else value

@register.filter
@stringfilter
def parse_header(value):
    """Parse HTTP header into name and value"""
    parts = value.split(':', 1)
    if len(parts) == 2:
        return {'name': parts[0].strip(), 'value': parts[1].strip()}
    return {'name': value, 'value': ''}

@register.filter
@stringfilter
def is_http_header(value):
    """Check if line is an HTTP header"""
    return bool(re.match(r'^[\w-]+: .+$', value))

@register.filter
def default_if_none(value, default=""):
    """Return default value if None"""
    return value if value is not None else default