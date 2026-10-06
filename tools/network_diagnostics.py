#!/usr/bin/env python3
"""Local read-only diagnostics. No sysctl writes, probes, keys or subscriptions."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess


def sysctl_value(name):
    try:
        result = subprocess.run(['sysctl', '-n', name], capture_output=True,
                                text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def summarize_xray(path):
    """Return only allowlisted fields; never include identities or addresses."""
    try:
        with Path(path).open() as source:
            text = source.read(2 * 1024 * 1024 + 1)
        if len(text) > 2 * 1024 * 1024:
            return {'error': 'config_too_large'}
        config = json.loads(text)
        inbounds = []
        for inbound in config.get('inbounds', []):
            stream = inbound.get('streamSettings', {})
            clients = inbound.get('settings', {}).get('clients', [])
            inbounds.append({
                'protocol': inbound.get('protocol'),
                'transport': stream.get('network', 'tcp'),
                'security': stream.get('security', 'none'),
                'vision_enabled': any(c.get('flow') == 'xtls-rprx-vision' for c in clients),
            })
        return {'inbounds': inbounds,
                'outbound_protocols': [o.get('protocol') for o in config.get('outbounds', [])],
                'outbound_mux_enabled': any(o.get('mux', {}).get('enabled') is True
                                            for o in config.get('outbounds', []))}
    except (OSError, ValueError, TypeError, AttributeError):
        return {'error': 'config_unreadable_or_invalid'}


def interface_mtu(directory=Path('/sys/class/net')):
    result = []
    try:
        entries = sorted(Path(directory).iterdir())
    except OSError:
        return result
    for entry in entries:
        if entry.name == 'lo':
            continue
        try:
            result.append({'interface': entry.name, 'mtu': int((entry / 'mtu').read_text())})
        except (OSError, ValueError):
            continue
    return result


def collect(config_path=None):
    result = {
        'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'local_read_only_no_external_probes',
        'kernel': platform.release(),
        'tcp': {
            'congestion_control': sysctl_value('net.ipv4.tcp_congestion_control'),
            'available_congestion_controls': sysctl_value('net.ipv4.tcp_available_congestion_control'),
            'default_qdisc': sysctl_value('net.core.default_qdisc'),
        },
        'interfaces': interface_mtu(),
        'notes': [
            'Local settings do not measure Instagram speed or prove VLESS reachability.',
            'The default qdisc may differ from active interface queue disciplines.',
            'BBR/MTU/QUIC changes require separate controlled client-side tests.',
        ],
    }
    try:
        result['load_average'] = list(os.getloadavg())
    except (OSError, AttributeError):
        result['load_average'] = None
    if config_path is not None:
        result['xray'] = summarize_xray(config_path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xray-config', type=Path, help='Explicit local config path; secrets are omitted')
    args = parser.parse_args()
    print(json.dumps(collect(args.xray_config), indent=2))


if __name__ == '__main__':
    main()
