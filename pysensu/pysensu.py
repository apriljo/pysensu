#!/usr/bin/env python

import requests


class Pysensu():
    def __init__(self, host, user=None, password=None, port=4567,
                 ssl=False, ssl_cert=None, ssl_key=None, ssl_verify=None):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.ssl = ssl
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.ssl_verify = ssl_verify
        self.api_url = self._build_api_url(host, user, password, port, ssl)

    def _build_api_url(self, host, user, password, port, ssl):
        if ssl is True:
            protocol = 'https'
        else:
            protocol = 'http'
        if user and password:
            credentials = "{}:{}@".format(user, password)
        elif (user and not password) or (password and not user):
            raise ValueError("Must specify both user and password, or neither")
        else:
            credentials = ""
        return "{}://{}{}:{}".format(protocol, credentials, host, port)

    def _api_call(self, url, method, data=None):
        if method in ("post", "get", "put", "delete"):
            request_kwargs = dict(
                method=method,
                url=url,
                json=data,
            )

            if self.ssl_cert and self.ssl_key:
                request_kwargs['cert'] = (self.ssl_cert, self.ssl_key)
            elif self.ssl_cert:
                request_kwargs['cert'] = self.ssl_cert

            if self.ssl_verify:
                request_kwargs['verify'] = self.ssl_verify

            return requests.request(**request_kwargs)
        else:
            raise ValueError("Invalid method: '{}'".format(method))

    def failed_request(self, method, response):
        msg = "Error {}: {} -> {}\nBody: {}".format(
            method, response.request.url, response.status_code, response.request.body)
        raise ValueError(msg)

    def format_url(self, path, *args):
        return "{}/{}".format(self.api_url, path.format(*args))

    def create_stash(self, client, check=None):
        if check:
            r = self._api_call(self.format_url("stashes/{}/{}", client, check), "post", "{}")
        else:
            r = self._api_call(self.format_url("stashes/{}", client), "post", "{}")
        if r.status_code != requests.codes.created:
            self.failed_request(method="creating stash", response=r)

    def delete_stash(self, client, check=None):
        if check:
            r = self._api_call(self.format_url("stashes/{}/{}", client, check), "delete")
        else:
            r = self._api_call(self.format_url("stashes/{}", client), "delete")
        if r.status_code != requests.codes.no_content:
            self.failed_request(method="deleting stash", response=r)

    def create_client(self, name, address, subscriptions=[], **kwargs):
        data = dict(
            name=name,
            address=address,
            subscriptions=subscriptions,
            **kwargs)

        r = self._api_call(self.format_url("clients"), "post", data=data)
        if r.status_code != requests.codes.created:
            self.failed_request(method="creating client", response=r)

    def delete_client(self, client):
        r = self._api_call(self.format_url("clients/{}", client), "delete")
        if r.status_code != requests.codes.accepted:
            self.failed_request(method="deleting client", response=r)

    def get_client_history(self, client):
        r = self._api_call(self.format_url("clients/{}/history", client), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting client history", response=r)
        return r.json()

    def get_client(self, client):
        r = self._api_call(self.format_url("clients/{}", client), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting client", response=r)
        return r.json()

    def get_all_clients(self):
        r = self._api_call("{}/clients".format(self.api_url), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting clients", response=r)
        return r.json()

    def get_all_stashes(self):
        r = self._api_call(self.format_url("stashes"), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting stashes", response=r)
        return r.json()

    def get_check(self, check):
        r = self._api_call(self.format_url("checks/{}", check), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting check", response=r)
        return r.json()

    def get_all_checks(self):
        r = self._api_call(self.format_url("checks"), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting checks", response=r)
        return r.json()

    def request_check(self, check, subscribers):
        data = {
            "check": check,
            "subscribers": subscribers
        }
        r = self._api_call(self.format_url("check/request"), "post", data=data)
        if r.status_code != requests.codes.accepted:
            self.failed_request(method="requesting check", response=r)

    def get_all_events(self):
        r = self._api_call(self.format_url("events"), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting events", response=r)
        return r.json()

    def get_all_client_events(self, client):
        r = self._api_call(self.format_url("events/{}", client), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting client events", response=r)
        return r.json()

    def get_event(self, client, check):
        r = self._api_call(self.format_url("events/{}/{}", client, check), "get")
        if r.status_code != requests.codes.ok:
            self.failed_request(method="getting event", response=r)
        return r.json()

    def delete_event(self, client, check):
        r = self._api_call(self.format_url("events/{}/{}", client, check), "delete")
        if r.status_code != requests.codes.accepted:
            self.failed_request(method="deleting event", response=r)

    def resolve_event(self, client, check):
        data = {
            "client": client,
            "check": check
        }
        r = self._api_call(self.format_url("event/resolve"), "post", data=data)
        if r.status_code != requests.codes.accepted:
            self.failed_request(method="getting client", response=r)
