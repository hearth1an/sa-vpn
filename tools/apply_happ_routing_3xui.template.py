#!/usr/bin/env python3
"""Source template. build.py produces the self-contained 3x-ui update script."""
import argparse
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

from routing import HAPP_ROUTING_PROFILE, PROFILE_NAMES, build_happ_profile, happ_routing_link  # @@ROUTING@@

PROFILE = HAPP_ROUTING_PROFILE
DB = Path('/etc/x-ui/x-ui.db')
RUNTIME = Path('/usr/local/x-ui/bin/config.json')
SETTINGS = ('subEnableRouting', 'subRoutingRules')


def routing_link(profile=None):
    return happ_routing_link(PROFILE if profile is None else profile)


def set_value(db, key, value):
    if not db.execute('update settings set value=? where key=?', (value, key)).rowcount:
        db.execute('insert into settings(key,value) values(?,?)', (key, value))


def apply_profile(profile, db_path, runtime_path):
    """Only mutate two subscription settings, with private backup and rollback."""
    db_path, runtime_path = Path(db_path), Path(runtime_path)
    if not db_path.is_file() or not runtime_path.is_file():
        raise ValueError('Не найдена действующая установка 3x-ui.')
    before_inbounds = json.loads(runtime_path.read_text())['inbounds']
    link = routing_link(profile)
    db = sqlite3.connect(db_path)
    try:
        # Check the expected schema before creating a backup or changing settings.
        before_rows = db.execute('select * from inbounds order by id').fetchall()
        old = {key: db.execute('select value from settings where key=?', (key,)).fetchone()
               for key in SETTINGS}
        backup = db_path.with_name(f'{db_path.name}.before-routing-{time.time_ns()}.bak')
        # Create exclusively with private permissions before SQLite writes keys.
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(backup)) as destination:
            db.backup(destination)

        try:
            set_value(db, 'subEnableRouting', 'true')
            set_value(db, 'subRoutingRules', link)
            db.commit()
            subprocess.run(['systemctl', 'restart', 'x-ui'], check=True)
            time.sleep(2)
            subprocess.run(['systemctl', 'is-active', '--quiet', 'x-ui'], check=True)
            if json.loads(runtime_path.read_text())['inbounds'] != before_inbounds:
                raise RuntimeError('3x-ui изменил VPN-входы при обновлении маршрутизации')
            if db.execute('select * from inbounds order by id').fetchall() != before_rows:
                raise RuntimeError('Изменились строки VPN-входов/пользователей в базе')
            actual = {key: db.execute('select value from settings where key=?', (key,)).fetchone()
                      for key in SETTINGS}
            if actual != {'subEnableRouting': ('true',), 'subRoutingRules': (link,)}:
                raise RuntimeError('3x-ui не сохранил профиль маршрутизации')
        except Exception:
            db.rollback()
            for key, value in old.items():
                if value is None:
                    db.execute('delete from settings where key=?', (key,))
                else:
                    set_value(db, key, value[0])
            db.commit()
            subprocess.run(['systemctl', 'restart', 'x-ui'], check=False)
            raise
        return backup
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description='Обновление маршрутизации Happ в 3x-ui')
    parser.add_argument('--profile', choices=PROFILE_NAMES, default='baseline')
    parser.add_argument('--dry-run', action='store_true', help='Показать профиль, ничего не менять')
    args = parser.parse_args()
    profile = build_happ_profile(args.profile)
    if args.dry_run:
        print(json.dumps(profile, ensure_ascii=False, indent=2))
        return
    if os.geteuid() != 0:
        parser.error('Запустите от root или через sudo.')
    backup = apply_profile(profile, DB, RUNTIME)
    print('Маршрутизация Happ обновлена; VPN-входы и пользовательские ключи сохранены.')
    print(f'Резервная копия: {backup}')
    print('Обновите подписку в Happ, дождитесь загрузки геофайлов и переподключитесь.')
    print('Перезапуск 3x-ui может кратковременно прервать активные подключения.')


if __name__ == '__main__':
    main()
