# -*- coding: utf-8 -*- vim:encoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

from django.conf import settings
from django.contrib.auth import authenticate, login

from accounts.models import User
from edumanage.views import lookupShibAttr


class ShibAdminAutoLoginMiddleware:
    """
    If /admin/ is protected by Shibboleth at the webserver level (e.g. mod_shib
    on the Apache <Location> for /admin/), this establishes the Django session
    from the Shibboleth attributes so staff don't also have to fill in the
    stock admin username/password form. Silently does nothing (falls through
    to the normal login form) if the Shibboleth attributes are absent, so it
    is safe to enable even before /admin/ is actually protected at the
    webserver level.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.path.startswith('/admin/') and
            not request.user.is_authenticated
        ):
            self.try_shib_login(request)
        return self.get_response(request)

    def try_shib_login(self, request):
        shib_username = getattr(settings, 'SHIB_USERNAME', None)
        if not shib_username:
            # Shibboleth attribute mapping isn't configured on this
            # deployment at all; nothing for this middleware to do.
            return
        username = lookupShibAttr(shib_username, request.META)
        if not username:
            return
        if not User.objects.filter(username__exact=username).exists():
            return
        mail = lookupShibAttr(getattr(settings, 'SHIB_MAIL', []), request.META)
        firstname = lookupShibAttr(getattr(settings, 'SHIB_FIRSTNAME', []), request.META)
        lastname = lookupShibAttr(getattr(settings, 'SHIB_LASTNAME', []), request.META)
        user = authenticate(
            request=request,
            username=username,
            firstname=firstname,
            lastname=lastname,
            mail=mail,
            authsource='shibboleth',
        )
        if user is not None and user.is_active:
            login(request, user)
