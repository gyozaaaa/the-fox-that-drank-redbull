#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import os
import time
import uuid

import httpx
import m3u8
import typer
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from loguru import logger

import config


class Wingfox(object):
    def __init__(self, video_id):
        self.video_id = video_id

        self.session = httpx.Client()
        self.session.headers['user-agent'] = config.UA

        self.token = None

    def login(self):
        if os.path.exists(config.AUTH_FILE):
            logger.info('using cached auth data')
            with open(config.AUTH_FILE, 'r') as f:
                data = json.load(f)

            self.session.headers['cookie'] = (
                f'PHPSESSID={data["php_sess_id"]}; '
                f'laravel_session={data["laravel_session"]}'
            )
            self.token = data['token']
            return

        self.session.get(
            config.INDEX_URL, headers={'x-requested-with': 'com.WingFox.app'}
        )

        php_session = self.session.cookies.get('PHPSESSID')
        resp = self.session.post(
            config.LOGIN_URL,
            params={
                'account': config.EMAIL,
                'password': config.PW
            },
            headers={'cookie': f'PHPSESSID={php_session}', 'x-isapi': '1'}
        )

        if resp.status_code != httpx.codes.OK:
            logger.error(f'Failed to login: [{resp.status_code}] {resp.text}')
            raise typer.Exit()

        self.token = resp.json()['data']['token']
        with open(config.AUTH_FILE, 'w') as f:
            f.write(
                json.dumps(
                    {
                        'php_sess_id': php_session,
                        'laravel_session': self.session.cookies.get('laravel_session'),
                        'token': self.token
                    }
                )
            )

    def get_video_url(self) -> str:
        headers = {
            'App-Common-Params': json.dumps(
                {
                    'app_version': config.APP_VERSION,
                    'lang': 'en',
                    # apparently this signature isn't validated ;D
                    'sign': uuid.uuid4().hex,
                    'system_type': 'android',
                    't': str(int(time.time())),
                    'token': self.token,
                    'debug': '1',
                    'channel': '3',
                    'channel_no': 'android',
                    'device_id': uuid.uuid4().hex
                }
            )
        }
        resp = self.session.get(
            config.GET_VIDEO_URL,
            params={'play_video_id': self.video_id},
            headers=headers
        )
        if resp.status_code != httpx.codes.OK:
            logger.error(f'Failed to get video_vid: [{resp.status_code}] {resp.text}')
            raise typer.Exit()

        return resp.json()['data']['video_vid']

    def get_video_json(self, video_vid: str) -> dict:
        resp = self.session.get(config.VIDEO_JSON_URL.format(video_vid))
        if resp.status_code != httpx.codes.OK:
            logger.error(f'Failed to get video_json: [{resp.status_code}] {resp.text}')
            raise typer.Exit()

        enc_json = resp.json()['body']

        hashed = hashlib.md5(video_vid.encode('utf-8')).hexdigest()
        key, iv = hashed[:16].encode(), hashed[16:].encode()

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        dec_json = cipher.decrypt(bytes.fromhex(enc_json)).rstrip(b'\x0c')

        return json.loads(base64.b64decode(dec_json).decode())

    def parse_m3u8(self, m3u8_data: str, token: str):
        playlist = m3u8.loads(m3u8_data)

        m3u8_key = playlist.keys[0]
        aes_key = self.session.get(m3u8_key.uri, params={'token': token}).content.hex()

        logger.info(f'enc aes key: {aes_key}')
        logger.info(f'iv: {m3u8_key.iv}')

        # the process of dl + merge is left as an exercise
        # the custom decryption is left for when i am feeling ambitious

    def get_key_token(self, video_vid: str):
        form_data = {
            'userId': config.USER_ID,
            'videoId': video_vid,
            'ts': str(int(time.time())),
            # used in latest version but not in previous versions and still works
            # when we don't include it
            # 'viewerName': '',
            'viewerId': 'dmlld2VyX2lk'
        }
        to_hash = ''
        for k in sorted(form_data):
            to_hash += f'{k}{form_data[k]}'
        to_hash = f'{config.TOKEN_SECRET}{to_hash}{config.TOKEN_SECRET}'
        form_data['sign'] = hashlib.md5(to_hash.encode()).hexdigest().upper()

        resp = self.session.post(config.TOKEN_URL, data=form_data)
        return resp.json()['data']['token']

    def get_m3u8_data(self, m3u8_url: str, seed_const: str, video_vid: str) -> tuple:
        resp = self.session.get(m3u8_url)
        enc_m3u8 = resp.json()['body']

        aes_key = hashlib.md5(
            f'{config.M3U8_SECRET}{seed_const}'.encode()
        ).hexdigest()[1:17].encode()

        cipher = AES.new(
            aes_key,
            AES.MODE_CBC,
            iv=bytes.fromhex(config.M3U8_IV)
        )
        dec = cipher.decrypt(base64.b64decode(enc_m3u8))
        data = unpad(dec, 16).decode()

        token = self.get_key_token(video_vid)
        return data, token

    def run(self):
        self.login()

        video_vid = self.get_video_url()

        video_json = self.get_video_json(video_vid)

        subs_url = video_json['video_srt']['English']
        m3u8_url = video_json['hls'][0]
        seed_const = video_json['seed_const']

        logger.info(f'subs url: {subs_url}')

        m3u8_data, token = self.get_m3u8_data(m3u8_url, seed_const, video_vid)
        self.parse_m3u8(m3u8_data, token)


# ex. 173392
def main(video_id: str):
    w = Wingfox(video_id)
    w.run()


if __name__ == '__main__':
    typer.run(main)
