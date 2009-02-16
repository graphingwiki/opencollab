# -*- coding: utf-8 -*-
"""
    @copyright: 2008 by Joachim Viide, Pekka Pietikäinen, Mika Seppänen  
    @license: MIT <http://www.opensource.org/licenses/mit-license.php>
"""
import urlparse
import xmlrpclib
import urllib
import socket
import httplib
import re

try:
    from curltransport import CURLTransport as CustomTransport
except ImportError:
    from transport import CustomTransport

class WikiFailure(Exception):
    pass

class AuthenticationFailed(WikiFailure):
    pass

class WikiAuthenticationFailed(AuthenticationFailed):
    pass

class HttpAuthenticationFailed(AuthenticationFailed):
    pass

class WikiFault(WikiFailure):
    def __init__(self, fault):
        faultString = fault.faultString.strip()
        faultLines = fault.faultString.split("\n")

        if faultLines:
            message = "There was an error in the wiki side (%s)" % faultLines[0]
        else:
            message = "There was an error in the wiki side"

        WikiFailure.__init__(self, message)
        self.fault = fault

def runWrapped(func, *args, **keys):
    try:
        result = func(*args, **keys)
    except xmlrpclib.Fault, f:
        if f.faultCode == "INVALID":
            raise WikiAuthenticationFailed(f.faultString)
        raise WikiFault(f)
    except xmlrpclib.ProtocolError, e:
        if e.errcode == 401:
            raise HttpAuthenticationFailed(e.errmsg)
        raise WikiFailure(e.errmsg)
    except (socket.gaierror, socket.error), (code, msg):
        raise WikiFailure(msg)
    except httplib.HTTPException, msg:
        raise WikiFailure(msg)

    if isinstance(result, dict) and "faultString" in result:
        faultString = result["faultString"]
        raise WikiFailure(faultString)
    return result

def urlQuote(string):
    if isinstance(string, unicode):
        string = string.encode("utf-8")
    return urllib.quote(string, "/:")
                               
class Wiki(object):
    WHOAMI_FORMAT = re.compile("^You are .*\. valid=(.+?)[\,\.]$", re.I)

    def __init__(self, url=None, sslPeerVerify=False):
        object.__init__(self)

        self.sslPeerVerify = sslPeerVerify

        self._url = urlQuote(url)
        self._httpCreds = None
        self._wikiCreds = None
        self._proxy = None

    def _getProxy(self):
        if self._proxy is not None:
            return self._proxy

        action = "action=xmlrpc2"
        scheme, netloc, path, _, _, _ = urlparse.urlparse(self._url)

        if self._httpCreds:
            username, password = map(urlQuote, self._httpCreds)
            netloc = "%s:%s@%s" % (username, password, netloc)
        url = urlparse.urlunparse((scheme, netloc, path, "", action, ""))

        if scheme == "http":
            transport = CustomTransport(CustomTransport.HTTP)
        else:
            transport = CustomTransport(CustomTransport.HTTPS,
                                        sslPeerVerify=self.sslPeerVerify)

        try:
            self._proxy = xmlrpclib.ServerProxy(url, transport, allow_none=True)
        except IOError, msg:
            raise WikiFailure(msg)

        return self._proxy

    def _doWikiAuth(self, username, password):
        token = self._getProxy().getAuthToken(username, password)
        if not token:
            raise WikiAuthenticationFailed("wiki authentication failed")
        return token
    
    def _authenticate(self, username, password):
        self._proxy = None
        self._wikiCreds = None
        self._httpCreds = None

        try:
            try:
                whoami = runWrapped(self._getProxy().WhoAmI)
            except HttpAuthenticationFailed:
                self._proxy = None
                self._httpCreds = username, password
                whoami = runWrapped(self._getProxy().WhoAmI)

            match = self.WHOAMI_FORMAT.match(whoami)
            if match is None:
                raise WikiFailure("WhoAmI action returned invalid data")

            valid = match.groups(1)
            if valid == "0":
                token = runWrapped(self._doWikiAuth, username, password)
                self._wikiCreds = token, username, password
        except:
            self._proxy = None
            self._wikiCreds = None
            self._httpCreds = None
            raise

    def _multiCall(self, name, *args):
        multiCall = xmlrpclib.MultiCall(self._getProxy())
        
        if self._wikiCreds:
            token, username, password = self._wikiCreds
            multiCall.applyAuthToken(token)

        method = getattr(multiCall, name)
        method(*args)
        results = multiCall()

        if not self._wikiCreds:
            return results[0]
        if results[0] == "SUCCESS":
            return results[1]

        raise WikiAuthenticationFailed(results[0]["failureString"])

    def request(self, name, *args):
        try:
            return runWrapped(self._multiCall, name, *args)
        except WikiAuthenticationFailed:
            _, username, password = self._wikiCreds
            token = runWrapped(self._doWikiAuth, username, password)
            self._wikiCreds = token, username, password
        return runWrapped(self._multiCall, name, *args)

    def authenticate(self, username, password):
        try:
            self._authenticate(username, password)
        except AuthenticationFailed:
            return False
        return True

import re
import md5
import sys
import random
import getpass

from meta import Meta 

class GraphingWiki(Wiki):
    DEFAULT_CHUNK = 256 * 1024

    def getPage(self, page):
        return self.request("getPage", page)

    def getPageHTML(self, page):
        return self.request("getPageHTML", page)

    def putPage(self, page, content):
        return self.request("putPage", page, content)

    def deletePage(self, page, comment=None):
        return self.request("DeletePage", page, comment)

    def putAttachment(self, page, filename, data, overwrite=False):
        data = xmlrpclib.Binary(data)
        return self.request("AttachFile", page, filename, 
                            "save", data, overwrite)

    def listAttachments(self, page):
        return self.request("AttachFile", page, "", "list", "", False)

    def getAttachment(self, page, filename):
        result = self.request("AttachFile", page, filename, "load", "", False)
        return str(result)

    def getAttachmentInfo(self, page, filename):
        return self.request("ChunkedAttachFile", page, filename, "info")

    def putAttachmentChunked(self, page, filename, seekableStream, 
                             chunksPerCheck=10, chunkSize=DEFAULT_CHUNK):
        count = 0
        total = 0
        digests = list()
        offsets = dict()
        
        while True:
            data = seekableStream.read(chunkSize)
            if not data:
                break

            digest = md5.new(data).hexdigest()
            digests.append(digest)

            length = len(data)
            offsets[digest] = total, length
            total += length

        while True:
            missing = self.request("ChunkedAttachFile", page, filename, 
                                   "reassembly", chunkSize, digests)
            if not missing:
                return

            done = total
            for digest in missing:
                offset, length = offsets[digest]
                done -= length

            yield done, total

            missing = random.sample(missing, min(len(missing), chunksPerCheck))
            for digest in missing:
                offset, length = offsets[digest]
                
                seekableStream.seek(offset)
                data = seekableStream.read(length)

                self.putAttachment(page, digest, data, overwrite=True)

                count += 1
                done += length
                yield done, total
                    
    def getAttachmentChunked(self, page, filename, chunkSize=DEFAULT_CHUNK):
        digest, size = self.getAttachmentInfo(page, filename)

        dataDigest = md5.new()
        current = 0

        while True:
            data = self.request("ChunkedAttachFile", page, filename, "load", 
                                current, current+chunkSize)
            data = str(data)
            if not data:
                break

            current += len(data)
            yield data, current, size

            dataDigest.update(data)
            if current > size:
                break

        if current != size:
            raise WikiFailure("data changed while reading")

        dataDigest = dataDigest.hexdigest()
        if dataDigest != digest:
            raise WikiFailure("data changed while reading")

    def getMeta(self, value):
        keysOnly = False
        results = self.request("GetMeta", value, keysOnly)

        keys = results.pop(0)
        pages = dict()

        for result in results:
            # Page names and meta keys seem to come from the wiki
            # UTF-8 encoded in contrast to the actual key values
            page = result.pop(0)
            meta = Meta()

            for key, values in zip(keys, result):
                if not values:
                    continue
                meta[key].update(values)

            pages[page] = meta

        return pages

    def setMeta(self, page, meta, replace=False, template=""):
        if replace:
            metaMode, categoryMode = "repl", "set"
        else:
            metaMode, categoryMode = "add", "add"

        keys = dict()
        for key, values in meta.iteritems():
            keys[key] = list(values)

        # If no categories specified, do not set categories to empty
        if not 'category' in keys:
            categoryMode = 'add'

        categories = keys.pop("category", list())
        createPageOnDemand = True

        return self.request("SetMeta", page, keys, metaMode,
                            createPageOnDemand, categoryMode, categories,
                            template)

import ConfigParser

def redirected(func, *args, **keys):
    oldStdout = sys.stdout
    sys.stdout = sys.stderr

    try:
        return func(*args, **keys)
    finally:
        sys.stdout = oldStdout

class CLIWiki(GraphingWiki):
    # A version of the GraphingWiki class intended for command line
    # usage. Automatically asks url, username and password should the
    # wiki need it.

    def __init__(self, url=None, config=None, configSection="creds", **keys):
        creds = None

        if config is not None:
            configparser = ConfigParser.ConfigParser()

            if configparser.read(config):
                try:
                    url = configparser.get(configSection, "url")
                except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                    pass

                try:
                    username = configparser.get(configSection, "username")
                    password = configparser.get(configSection, "password")
                    creds = username, password
                except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                    pass

        if url is None:
            url = redirected(raw_input, "Wiki:")

        super(CLIWiki, self).__init__(url, **keys)

        if creds is not None:
            self.authenticate(*creds)

    def authenticate(self, username=None, password=None):
        if username is None:
            username = redirected(raw_input, "Username:")
        if password is None:
            password = redirected(getpass.getpass, "Password:")
        return super(CLIWiki, self).authenticate(username, password)

    def request(self, name, *args):
        while True:
            try:
                return super(CLIWiki, self).request(name, *args)
            except AuthenticationFailed, f:
                while True:
                    print >> sys.stderr, "Authorization required."
                    if self.authenticate():
                        break
