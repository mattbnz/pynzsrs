#------------------------------------------------------------------------------
# Copyright 2012 Matt Brown <matt@mattb.net.nz>
#
# pynzsrs is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# pynzsrs is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# pynzsrs; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307  USA
#------------------------------------------------------------------------------
import gnupg
import httplib
import socket
import ssl
import urllib
import urlparse

import options

VERSION = '0.1'


class HTTPSConnectionWithCA(httplib.HTTPSConnection):
    """An HTTPS connection that validates the server cert against a CA."""
    
    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, ca_certs=None):
        httplib.HTTPSConnection.__init__(self, host, port, key_file, cert_file,
                strict, timeout, source_address)
        self.ca_certs = ca_certs

    def connect(self):
        "Connect to a host on a given (SSL) port."       
        sock = socket.create_connection((self.host, self.port),
                self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                ca_certs=self.ca_certs, cert_reqs=ssl.CERT_REQUIRED)
        # TODO(mattb): We should probably also validate the CN/SAN matches teh
        # host here, but for now since the SRS has their own CA, assume that
        # any cert signed by their CA is safe.


class SRSClient(object):
    """SRS low-level client interface.

    This class implements the registry protocol defined in
    http://tools.ietf.org/html/draft-nzrs-srs-02

    It accepts messages in XML or JSON format.
    """

    def __init__(self, argv=None):
        self.options = options.SRSOptions(argv)
        self.gpg = gnupg.GPG(keyring=self.options.gpg_secret)
        
    def SendXML(self, xml):
        """Send an XML formatted request and return the response.

        Args:
            xml: Unicode string containing a valid XML request for the SRS.

        Returns:
            A unicode string representing the XML response from the SRS.
        """
        params = {
                'n': self.options.registrar_id,
                'r': xml,
                's': self._SignRequest(xml)
        }
        params = urllib.urlencode(params)
        if not self.options.url.startswith('http'):
            o = urlparse.urlparse('https://%s' % self.options.url)
        else:
            o = urlparse.urlparse(self.options.url)
        conn = HTTPSConnectionWithCA(o[1], ca_certs=self.options.srs_ca)
        conn.request('POST', o[2], params, self._GetHeaders())
        response = conn.getresponse()
        if response.status != 200:
            raise Exception('Request Failed: %s %s' %
                    (response.status, response.reason))
        rdict = urlparse.parse_qs(response.read())
        if 'r' not in rdict:
            raise Exception('Malformed response. r parameter missing!')
        if 's' not in rdict:
            raise Exception('Malformed response. s parameter missing!')
        if not self._ValidateSignature(rdict['r'], rdict['s']):
            raise Exception('Invalid response. Signature incorrect!')
        return rdict['r']

    def _GetHeaders(self):
        """Returns a dict of headers for an SRS request."""
        return {'Content-type': 'application/x-www-form-urlencoded',
                'User-Agent': 'pynzsrs/%s' % VERSION}

    def _SignRequest(self, xml):
        """Returns a detached OpenGPG signature for the specified xml document.

        Args:
            xml: Unicode string containing a valid XML request for the SRS.

        Returns:
            A unicode string representing the detached ascii armored signature
            for the request in xml.
        """
        passphrase = None
        if getattr(self.options, 'gpg_passphrase', None):
            passphrase = self.option.gpg_passphrase
        elif getattr(self.options, 'gpg_passphrase_file', None):
            with open(self.options.gpg_passphrase_file, 'r') as fp:
                passphrase = fp.read()

        return str(self.gpg.sign(xml, keyid=self.options.gpg_id,
            passphrase=passphrase, detach=True))

    def _ValidateSignature(self, response, signature):
        """Validates the signature for response is correct.
        
        Args:
            response: UTF-8 encoded string containing the response.
            signature: UTF-8 encoded string containing the ascii armored
                signature for response.

        Returns:
            A boolean indicating if the signature was valid or not.
        """
        return self.gpg.verify_file(signature, response)
