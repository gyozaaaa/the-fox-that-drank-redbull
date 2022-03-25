# -*- coding: utf-8 -*-
from local_config import *

UA = 'Mozilla/5.0 (Linux; Android 9; moto g(6) play Build/PPP29.118-68; wv) ' \
     'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile ' \
     'Safari/537.36 isApp/com.WingFox.app'

APP_VERSION = '1.1.16'

INDEX_URL = 'https://api.wingfox.com/app/service_index'
LOGIN_URL = 'https://api.wingfox.com/auth/login'
GET_VIDEO_URL = 'https://api.wingfox.com/app/album/get_video_url'
VIDEO_JSON_URL = 'https://player.polyv.net/secure/{}.json'
TOKEN_URL = 'https://hls.videocc.net/service/v1/token'

# these 2 come from the decrypted polv_token
USER_ID = '9215d65496'
TOKEN_SECRET = 'HiJuZtgRpI'

M3U8_SECRET = 'NTQ1ZjhmY2QtMzk3OS00NWZhLTkxNjktYzk3NTlhNDNhNTQ4#'
# comes from libpolyvplayer.so ffp_decrypt_pdx_0()
# can also be seen in browser polv-wasm-player.js just search for the M3U8_SECRET and
# this IV will be nearby
M3U8_IV = '01 01 02 03 05 08 0d 15 22 15 0d 08 05 03 02 01'
