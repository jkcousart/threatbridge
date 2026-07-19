import json

from django import template

register = template.Library()


@register.filter
def pretty_json(value):
    try:
        return json.dumps(value, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def dict_get(value, key):
    if not isinstance(value, dict):
        return None
    return value.get(key)
