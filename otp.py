import hashlib
from base64 import b64encode, b64decode
import hmac
import random

from six.moves.urllib.parse import urlencode

__all__ = ['YubiOTP']

YUBICO_API_SERVER_URLS = (
    'https://api.yubico.com/wsapi/2.0/verify/',
    'https://api2.yubico.com/wsapi/2.0/verify/',
    'https://api3.yubico.com/wsapi/2.0/verify/',
    'https://api4.yubico.com/wsapi/2.0/verify/',
    'https://api5.yubico.com/wsapi/2.0/verify/',
)

try:
    #We want requests because it does sensible SSL verification,
    #but if not installed, we *require* the secret_key so the data is verified
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False
    from six.moves.urllib.request import urlopen

try:
    #Prefer OpenSSL for generating seeds/nonces if available
    import OpenSSL
    HAVE_OPENSSL = True
    random.seed(OpenSSL.rand.bytes(16))
except ImportError:
    HAVE_OPENSSL = False
    try:
        with open('/dev/urandom') as urand:
            random.seed(urand.read(16))
    except IOError:
        pass


def get(url):
    """Wraps an HTTP get in the best library available"""
    if HAVE_REQUESTS:
        return requests.get(url).text
    return urlopen(url).read()

def rand_bytes(count):
    """Gets random bytes as bestly as candoo"""
    if HAVE_OPENSSL:
        return OpenSSL.rand.bytes(count)
    return ''.join([random.choice([chr(y) for y in range(256)]) for x in range(count)])


class YubiOTP(object):
    """
    A simple interface for OTP authentication a Yubikey authentication server
    """
    def __init__(self, otp, client_id, secret_key=None, **kwargs):
        self.otp = otp
        self.secret_key = secret_key
        self.client_id = client_id
        self.response = None
        self.request_dict = None
        self.response_dict = None
        self.url = kwargs.get('url', random.choice(YUBICO_API_SERVER_URLS))
        if (not self.url.startswith('https://') or not 
            HAVE_REQUESTS) and secret_key is None:
            raise ValueError("Cannot verify authenticity with given parameters."\
                "Please provide your secret_key or install requests")

    def _kv_pairs(self, vals):
        """This is urllib2.urlencode without the encoding of unsafe chars"""
        return '&'.join([k + '=' + str(v) for k, v in sorted(vals.items())])

    def validate_hmac(self):
        """combines all response paramters as a string and validates the keyed
        MAC of those values matches the response MAC"""
        if self.secret_key is None:
            return
        mac = b64decode(self.response_dict.pop('h'))
        msg = self._kv_pairs(self.response_dict)
        if hmac.HMAC(self.secret_key, msg, hashlib.sha1).digest() != mac:
            raise ValueError("The server returned an invalid MAC")

    def generate_hmac(self):
        """Yubikeyv2.0 uses a SHA1 based HMAC with the API key as the key and
        concatenated the k,v pairs from the response in alphabetical order i.e.
        'a=1&b=2' not 'b=1a=2'
        """
        #remove the hmac key if it exists in the request (it shouldn't)
        self.request_dict.pop('h', None)
        if self.secret_key is None:
            return
        msg = self._kv_pairs(self.request_dict)
        self.request_dict['h'] = b64encode(hmac.HMAC(
            self.secret_key,
            msg,
            hashlib.sha1).digest())

    def generate_nonce(self):
        """The Yubico v2.0 documentaion is unclear for the value of the nonce:
            'A 16 to 40 character long string with random unique data'.
        Random *and* unique cannot both be guaranteed.
        1. More than one client can be used with the same Yubikey.
        2. A randomly value could be generated more than once (unlikely).
        If used for crypto purposes, random is better than unique.
        """
        return hashlib.sha1(rand_bytes(24)).hexdigest()

    def get_query_url(self):
        """generates the full HTTP GET url"""
        return self.url + 'verify?' + urlencode(self.request_dict)

    def parse_response(self):
        """convert response into a dictionary"""
        return {k:v for k, v in [x.split('=', 1) for x in self.response.split('\r\n')]}

    def get_api_response(self):
        """Perform the actual query against the Yubikey servers"""
        self.request_dict = {
            'id':str(self.client_id),
            'otp':self.otp,
            'nonce':self.generate_nonce(),
        }
        self.generate_hmac()
        self.response = get(self.get_query_url()).strip('\r\n\r\n')

    def verify(self):
        """This method does the actual checking of request/response values
        and raises ValueError when a failure occurs.
        """
        self.get_api_response()
        self.response_dict = self.parse_response()
        if self.response_dict['otp'] != self.otp:
            raise ValueError("Suspicious:request/response OTP mismatch: %s:%s"
                % (self.response_dict, self.response_dict)
            )
        if self.response_dict['status'] != 'OK':
            raise ValueError("The given OTP did not validate - %s:%s"
                %(self.otp, self.response_dict['status'])
            )
        self.validate_hmac()
        return self.response_dict
        
if __name__ == '__main__':
    try:
        from keys import *
    except ImportError:
        SECRET_KEY = raw_input("paste your Yubikey secret_key (base64 encoded)")
        CLIENT_ID = raw_input("enter your client id (integer)")
    while True:
        try:
            otp = YubiOTP(raw_input("Press the Yubkey button:"), CLIENT_ID, SECRET_KEY)
            otp.verify()
            print "OKAY!"
        except ValueError:
            print "failure"
        except KeyError:
            print otp.response_dict
            print otp.request_dict

