# OpenVPN Access Server post_auth script for iVALT 2FA.
# Version: 1.0
#
# This script can be used with LOCAL, PAM, LDAP, and RADIUS authentication.
# It adds an additional check when authentication is done through the VPN connection
# via a MFA Challenge using iVALT Application.
#
# Contributions by:
# Johan Draaisma
# Teodor Moroz
# Brandon Giron
#
# Full documentation at:
# https://openvpn.net/static-links/post-auth-custom-authentication
#
# Script last updated in October 2025
import os
import re
import datetime
import time
from pyovpn.plugin import *

# this function is called by the Access Server after normal VPN or web authentication
def post_auth(authcred, attributes, authret, info):

    if info.get('auth_method') in ('session', 'autologin'):
        return authret

    if attributes.get('vpn_auth'):
        # Here is where you put extra checks for normal native-authenticated users
        print("Native auth passed, running extra PAS checks...")
        status, mobile = ivalt_get_mobile_by_email(authcred['username'])
        start_time = time.time()
        verified = ""
        msg = "AUTHENTICATION_FAILED"
        print(mobile)

        if status:
            is_success = ivalt_auth_request_sent(mobile)
            print('Notification sent to user - ', is_success)

            while (time.time() - start_time) < 60:  # Run for 60 seconds
                print("Verifying...")
                is_success, error_msg = ivalt_auth_request_verify(mobile)

                if not is_success:
                    if error_msg in ['INVALID_TIMEZONE', 'INVALID_GEOFENCE']:
                        msg = error_msg
                        print(f"{msg} - Exiting due to error")
                        break  # Exit the loop immediately on specific errors
                else:
                    verified = True
                    print("Verification successful!")
                    break  # Exit the loop on success

                time.sleep(5)  # Wait for 5 seconds before retrying
        else:
            msg = mobile if mobile is not None else msg
        # Redirect back with the msg
        if not verified:
            authret['status'] = FAIL  # Fail the authentication
            authret['reason'] = msg  # Reason for failure
            authret['client_reason'] = msg  # Reason for failure
            return authret
        else:
            authret['status'] = SUCCEED

    return authret


from typing import Tuple, Any
IVALT_SECRET_KEY = "<ivalt_secret_key>"
import requests


def ivalt_auth_request_sent(mobile: str) -> dict:
    # send notification to user's mobile to authenticate
    url = "https://api.ivalt.com/biometric-auth-request"
    headers = {
        "x-api-key": IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "mobile": mobile
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
    except:
        return False

    if response.status_code != 200:
        return False

    return True


def ivalt_auth_request_verify(mobile: str) -> dict:
    # verify user's mobile to authenticate
    url = "https://api.ivalt.com/biometric-geo-fence-auth-results"
    headers = {
        "x-api-key": IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "mobile": mobile
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
    except:
        return False, None

    if response.status_code != 200:
        response = response.json()
        if 'timezone' in response.get('error', {}).get('detail', ''):
            return False, 'INVALID_TIMEZONE'
        if 'geofencing' in response.get('error', {}).get('detail', ''):
            return False, 'INVALID_GEOFENCE'
        return False, None

    return True, None


def ivalt_get_mobile_by_email(email: str) -> tuple[bool, Any]:
    # send notification to user's mobile to authenticate
    url = "https://api.ivalt.com/get-user-by-email"
    headers = {
        "x-api-key": IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "email": email
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
    except:
        return False, None

    res = response.json()
    # print(response.status_code)
    if response.status_code != 200:
        return False, res['error']['detail']

    return True, res['data']['details']['mobile_with_country_code']
