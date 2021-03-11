import socket
import httplib


try:
    # Try to use the new ssl module included by default from Python
    # 2.6 onwards.
    import ssl
except ImportError:
    class HTTPSConnection(httplib.HTTPSConnection):
        def __init__(self, *args, **keys):
            if keys.pop("verify_cert", True):
                raise socket.sslerror("module 'ssl' required for " +
                                      "certificate verification")
            keys.pop("ca_certs", None)

            httplib.HTTPSConnection.__init__(self, *args, **keys)
else:
    def wrap_socket(sock, hostname, verify_cert, ca_certs):
        context = ssl.create_default_context()

        if not verify_cert:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context.wrap_socket(sock)

        if ca_certs is not None:
            context.load_verify_locations(ca_certs)

        return context.wrap_socket(sock, server_hostname=hostname)

    class HTTPSConnection(httplib.HTTPSConnection):
        def __init__(self, *args, **keys):
            self.verify_cert = keys.pop("verify_cert", False)
            self.ca_certs = keys.pop("ca_certs", None)

            httplib.HTTPSConnection.__init__(self, *args, **keys)

        def connect(self):
            for info in socket.getaddrinfo(self.host, self.port,
                                           0, socket.SOCK_STREAM):
                family, type, proto, _, addr = info

                plain = socket.socket(family, type, proto)
                plain.connect(addr)

                self.sock = wrap_socket(plain,
                                        self.host,
                                        verify_cert=self.verify_cert,
                                        ca_certs=self.ca_certs)

                return
