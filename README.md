yubihebi
==========

Python client for YubiKey v2.0 OTP

**Basic Usage**
---------------

        from yubihebi.otp import YubiOTP
        
        otp = YubiOTP(raw_input("Please press the button on your YubiKey"), my_client_id, my_secret_key)
        
        try:
            otp.verify()
            print "OTP is valid succeeded"
        except ValueError as e:
            print "verification failed:%s" % e
        
That's it!

The verification defaults to using Yubico's servers, though if you host your own internal authentication server, you can pass `url='https://myserver.myhost.mytld/api_path'` to the constructor.


**Notes**
----------
* If the URL is not HTTPS, you **must** provide your secret key.

* Installing [python-requests](http://docs.python-requests.org/en/latest/ "requests is awesome") is *highly* recommended.  This will ensure proper SSL host verification.  Otherwise urllib2 is used and its SSL support is broken.

* Installing pyOpenSSL is also recommended but not required.
