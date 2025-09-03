from django import template
import json

register = template.Library()

@register.filter(name='json_escape')
def json_escape(value):
    """Safely convert a value to JSON string for use in JavaScript"""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return '""'
