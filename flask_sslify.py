# -*- coding: utf-8 -*-
from urlparse import urlparse, urlunparse
from flask import request, redirect, current_app

YEAR_IN_SECS = 31536000


class SSLify(object):
    """Secures your Flask App."""

    def __init__(self, app=None, age=YEAR_IN_SECS, subdomains=False, permanent=False, add_www=False):
        self.hsts_age = age
        self.hsts_include_subdomains = subdomains
        self.permanent = permanent
        self.add_www = add_www

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Configures the configured Flask app to enforce SSL."""

        app.before_request(self.redirect_to_ssl)
        app.after_request(self.set_hsts_header)

    @property
    def hsts_header(self):
        """Returns the proper HSTS policy."""
        hsts_policy = 'max-age={0}'.format(self.hsts_age)

        if self.hsts_include_subdomains:
            hsts_policy += '; includeSubDomains'

        return hsts_policy

    def redirect_to_ssl(self):
        url = request.url
        modified = False
        code = 301 if self.permanent else 302
        if self.add_www:
            urlparts = urlparse(url)
            if not urlparts.netloc.startswith('www.'):
                urlparts_list = list(urlparts)
                urlparts_list[1] = 'www.' + urlparts.netloc
                url = urlunparse(urlparts_list)
                modified = True
        # Should we redirect?
        criteria = [
            request.is_secure,
            current_app.debug,
            request.headers.get('X-Forwarded-Proto', 'http') == 'https'
        ]

        if not any(criteria):
            if url.startswith('http://'):
                url = url.replace('http://', 'https://', 1)
                modified = True

        if modified:
            return redirect(url, code=code)

    def set_hsts_header(self, response):
        """Adds HSTS header to each response."""
        if request.is_secure:
            response.headers.setdefault('Strict-Transport-Security', self.hsts_header)
        return response
