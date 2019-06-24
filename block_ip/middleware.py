from django.http import HttpResponseForbidden
from django.conf import settings
from django.contrib.auth import logout
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin

from .models import BlockIP


def get_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_ip_in_nets(ip, nets):
    for net in nets:
        if ip in net:
            return True
    return False


class BlockIPMiddleware(MiddlewareMixin):
    def process_request(self, request):
        is_banned = False

        ip = get_ip(request)
        # TODO: Look into something more optimized for large numbers
        # of blocks. https://github.com/jimfunk/django-postgresql-netfields
        block_ips = cache.get('blockip:list')
        if block_ips is None:
            block_ips = BlockIP.objects.all()
            cache.set('blockip:list', block_ips)
        deny_ips = [i.get_network() for i in block_ips]

        for net in deny_ips:
            if ip in net:
                is_banned = True
                break

        if is_banned:
            logout(request)
            return HttpResponseForbidden("")
