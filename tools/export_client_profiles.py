#!/usr/bin/env python3
"""Print opt-in, credential-free fragments; never modify a client or server."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from routing import (PROFILE_NAMES, build_happ_profile, happ_routing_link,
                     anydesk_singbox_rule, anydesk_android_headers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=('happ-json', 'happ-link', 'singbox-anydesk',
                                             'happ-android-anydesk'), default='happ-json')
    parser.add_argument('--profile', choices=PROFILE_NAMES, default='baseline')
    parser.add_argument('--provider-id', help='Existing registered Happ Provider ID')
    args = parser.parse_args()
    if args.format == 'happ-link':
        # Add rather than onadd: exporting an experiment never activates it.
        print(happ_routing_link(build_happ_profile(args.profile), activate=False))
    elif args.format == 'singbox-anydesk':
        print(json.dumps(anydesk_singbox_rule(), indent=2))
    elif args.format == 'happ-android-anydesk':
        try:
            headers = anydesk_android_headers(args.provider_id)
        except ValueError as error:
            parser.error(str(error))
        for key, value in headers.items():
            print(f'{key}: {value}')
    else:
        print(json.dumps(build_happ_profile(args.profile), indent=2))


if __name__ == '__main__':
    main()
