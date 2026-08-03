import os
import re
import gzip
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus, urlparse, parse_qs

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------------------------------------------------------
# CONFIGURATION & CONSTANTS
# -----------------------------------------------------------------------------
DOMAINS: List[str] = [
    "https://kisskh.do",
    "https://kisskh.co",
    "https://kisskh.me",
    "https://kisskh.asia"
]

GAS_SUB_ENDPOINT: str = os.getenv(
    "GAS_SUB_ENDPOINT",
    "https://script.google.com/macros/s/AKfycbyq6hTj0ZhlinYC6xbggtgo166tp6XaDKBCGtnYk8uOfYBUFwwxBui0sGXiu_zIFmA/exec?id="
)

DEFAULT_HEADERS: Dict[str, str] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
}

KEY: bytes = bytes.fromhex("4F6BDAA39E2F8CB07F5E722D9EDEF314")
IV: bytes = bytes.fromhex("01504AF356E619CF2E42BBA68C3F70F9")
VID_TOKEN: str = "62f176f3bb1b5b8e70e39932ad34a0c7"

DECRYPT_KEYS: Dict[str, Dict[str, bytes]] = {
    "txt": {"key": b"8056483646328763", "iv": b"6852612370185273"},
    "txt1": {"key": b"AmSmZVcH93UQUezi", "iv": b"ReBKWW8cqdjPEnF6"},
    "default": {"key": b"sWODXX04QRTkHdlZ", "iv": b"8pwhapJeC4hrS9hO"},
}

LANG_MAP: Dict[str, str] = {
    'en': 'English', 'eng': 'English', 'english': 'English',
    'es': 'Spanish', 'spa': 'Spanish', 'spanish': 'Spanish',
    'fr': 'French', 'fre': 'French', 'fra': 'French', 'french': 'French',
    'de': 'German', 'ger': 'German', 'deu': 'German', 'german': 'German',
    'it': 'Italian', 'ita': 'Italian', 'italian': 'Italian',
    'pt': 'Portuguese', 'por': 'Portuguese', 'portuguese': 'Portuguese',
    'ru': 'Russian', 'rus': 'Russian', 'russian': 'Russian',
    'zh': 'Chinese', 'zho': 'Chinese', 'chi': 'Chinese', 'chinese': 'Chinese',
    'ja': 'Japanese', 'jpn': 'Japanese', 'japanese': 'Japanese',
    'ko': 'Korean', 'kor': 'Korean', 'korean': 'Korean',
    'id': 'Indonesian', 'ind': 'Indonesian', 'indonesian': 'Indonesian',
    'vi': 'Vietnamese', 'vie': 'Vietnamese', 'vietnamese': 'Vietnamese',
    'th': 'Thai', 'tha': 'Thai', 'thai': 'Thai',
    'ar': 'Arabic', 'ara': 'Arabic', 'arb': 'Arabic', 'arabic': 'Arabic',
    'hi': 'Hindi', 'hin': 'Hindi', 'hindi': 'Hindi',
    'tl': 'Tagalog', 'tgl': 'Tagalog', 'tagalog': 'Tagalog',
    'fil': 'Filipino', 'filipino': 'Filipino',
    'tr': 'Turkish', 'tur': 'Turkish', 'turkish': 'Turkish',
    'pl': 'Polish', 'pol': 'Polish', 'polish': 'Polish',
    'nl': 'Dutch', 'nld': 'Dutch', 'dut': 'Dutch', 'dutch': 'Dutch',
    'sv': 'Swedish', 'swe': 'Swedish', 'swedish': 'Swedish',
    'ms': 'Malay', 'msa': 'Malay', 'may': 'Malay', 'malay': 'Malay'
}


# -----------------------------------------------------------------------------
# CORS & UTILS
# -----------------------------------------------------------------------------
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,OPTIONS'
    return response


def create_session(referer_url: str) -> requests.Session:
    """Creates a standard requests Session configured with dynamic Referer/Origin."""
    session = requests.Session()
    headers = DEFAULT_HEADERS.copy()
    headers['Referer'] = referer_url
    headers['Origin'] = referer_url.rsplit('/', 1)[0] if '/' in referer_url else referer_url
    session.headers.update(headers)
    return session


def sanitize_title(raw_title: str) -> str:
    cleaned = re.sub(r'[^a-zA-Z0-9\s]', ' ', raw_title)
    return ' '.join(cleaned.split()).strip()


def is_valid_url(url: str) -> bool:
    """Validates URL format to safeguard against SSRF."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def hash_func(string: str) -> int:
    hash_val = 0
    for char in string:
        char_code = ord(char)
        int32_hash = hash_val & 0xFFFFFFFF
        if int32_hash > 0x7FFFFFFF:
            int32_hash -= 0x100000000
        shifted = (int32_hash << 5) & 0xFFFFFFFF
        if shifted > 0x7FFFFFFF:
            shifted -= 0x100000000
        hash_val = shifted - hash_val + char_code
    return hash_val


def generate_kkey(episode_id: str) -> str:
    payload_arr = ['', episode_id, '', 'mg3c3b04ba', '2.8.10', VID_TOKEN, '4830201', 'kisskh', 'kisskh', 'kisskh', 'kisskh', 'kisskh', 'kisskh', '00', '']
    joined = '|'.join(payload_arr)
    payload_arr.insert(1, str(hash_func(joined)))
    final = '|'.join(payload_arr)

    data_bytes = final.encode('utf-8')
    padded_data = pad(data_bytes, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(padded_data)
    return encrypted.hex().upper()


def decrypt_subtitle_bytes(raw_bytes: bytes, sub_url: str) -> str:
    sub_type = "default"
    path = urlparse(sub_url).path.lower()
    
    if path.endswith(".txt1"):
        sub_type = "txt1"
    elif path.endswith(".txt"):
        sub_type = "txt"

    key_info = DECRYPT_KEYS[sub_type]
    cipher = AES.new(key_info["key"], AES.MODE_CBC, key_info["iv"])

    try:
        decrypted = cipher.decrypt(raw_bytes)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8', errors='ignore')
    except Exception:
        return raw_bytes.decode('utf-8', errors='ignore')


def format_to_vtt(text: str) -> str:
    """Ensures subtitle content is valid WebVTT format."""
    text = text.strip()
    if not text.startswith("WEBVTT"):
        text = re.sub(r'(\d{2}:\d{2}:\d{2}),(\d{3})', r'\1.\2', text)
        text = "WEBVTT\n\n" + text
    return text


# -----------------------------------------------------------------------------
# EXTERNAL STREMIO ADDON SUBTITLE PROVIDERS
# -----------------------------------------------------------------------------
def get_imdb_id(title: str) -> Optional[str]:
    """Resolves IMDb ID using IMDb public suggestion API."""
    try:
        clean_t = sanitize_title(title).lower()
        if not clean_t:
            return None
        first_char = clean_t[0] if clean_t[0].isalnum() else 'a'
        slug = clean_t.replace(' ', '_')
        url = f"https://v2.sg.media-imdb.com/suggestion/{first_char}/{slug}.json"
        
        resp = requests.get(url, timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("d", [])
            for item in results:
                item_id = item.get("id", "")
                if item_id.startswith("tt"):
                    return item_id
    except Exception as e:
        logging.error(f"IMDb resolution error for '{title}': {e}")
    return None


def fetch_stremio_subtitles(title: str, episode_num: str = "1", season_num: str = "1") -> List[Dict[str, Any]]:
    """Queries OpenSubtitles v3 and YaStream using Stremio Subtitle Addon Protocol."""
    subs = []
    if not title:
        return subs

    imdb_id = get_imdb_id(title)
    if not imdb_id:
        logging.warning(f"Could not resolve IMDb ID for external subtitle lookup: '{title}'")
        return subs

    stremio_addons = [
        "https://opensubtitles-v3.strem.io",
        "https://yastream.tamthai.de"
    ]

    id_formats = [
        f"series/{imdb_id}:{season_num}:{episode_num}.json",
        f"movie/{imdb_id}.json"
    ]

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    for addon_base in stremio_addons:
        for id_fmt in id_formats:
            target_url = f"{addon_base}/subtitles/{id_fmt}"
            try:
                resp = session.get(target_url, timeout=2.5)
                if resp.status_code == 200:
                    data = resp.json()
                    sub_list = data.get("subtitles", [])
                    for sub in sub_list:
                        sub_url = sub.get("url")
                        if not sub_url:
                            continue
                        raw_lang = (sub.get("lang") or "eng").lower().strip()
                        clean_lang = LANG_MAP.get(raw_lang, raw_lang.capitalize() or "English")
                        
                        proxy_url = f"/api/sub/decrypt?url={quote_plus(sub_url)}"
                        subs.append({
                            "language": clean_lang,
                            "code": raw_lang[:2],
                            "decrypted_url": proxy_url,
                            "original_src": sub_url,
                            "default": len(subs) == 0
                        })
                    if subs:
                        break
            except Exception as e:
                logging.error(f"Error querying {addon_base}: {e}")
        if subs:
            break

    return subs


# -----------------------------------------------------------------------------
# KISSKH SUBTITLE EXTRACTION HELPERS
# -----------------------------------------------------------------------------
def fetch_subtitles_from_gas(episode_id: str) -> List[Dict[str, Any]]:
    """Fetches and normalizes KissKH subtitles using external proxy script."""
    subs = []
    gas_url = f"{GAS_SUB_ENDPOINT}{episode_id}"

    try:
        response = requests.get(gas_url, timeout=3, allow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            sub_list = data if isinstance(data, list) else (data.get("subtitles") or data.get("subs") or [] if isinstance(data, dict) else [])
            
            for idx, item in enumerate(sub_list):
                if not isinstance(item, dict):
                    continue
                src = item.get("src") or item.get("url") or item.get("file")
                if src:
                    lang_name = str(item.get("label") or item.get("land") or item.get("language") or "English").strip()
                    raw_lang = lang_name.lower()
                    clean_lang = LANG_MAP.get(raw_lang, lang_name.capitalize() if lang_name else "English")
                    proxy_url = f"/api/sub/decrypt?url={quote_plus(src)}"
                    subs.append({
                        "language": clean_lang,
                        "code": raw_lang[:2],
                        "decrypted_url": proxy_url,
                        "original_src": src,
                        "default": bool(item.get("default", idx == 0))
                    })
    except Exception as e:
        logging.error(f"Google Apps Script subtitle fetch failed for ep {episode_id}: {e}")

    return subs


def extract_third_party_subtitles(third_party_url: str) -> List[Dict[str, Any]]:
    """Extracts and proxies subtitles attached to third_party links or embeds."""
    subs = []
    if not third_party_url:
        return subs

    session = create_session("https://kisskh.do/")

    try:
        parsed = urlparse(third_party_url)
        params = parse_qs(parsed.query)

        for key, values in params.items():
            if key.startswith('caption_'):
                index = key.split('_')[-1]
                caption_url = values[0]
                
                if len(caption_url.rsplit('/', 1)[-1]) > 0 and '.' in caption_url.rsplit('/', 1)[-1]:
                    lang_key = f"sub_{index}"
                    raw_lang = params.get(lang_key, ['English'])[0].lower().strip()
                    clean_lang = LANG_MAP.get(raw_lang, raw_lang.capitalize() or 'English')

                    proxy_url = f"/api/sub/decrypt?url={quote_plus(caption_url)}"
                    subs.append({
                        "language": clean_lang,
                        "code": raw_lang,
                        "decrypted_url": proxy_url,
                        "original_src": caption_url,
                        "default": index == '1'
                    })
    except Exception as e:
        logging.error(f"Failed parsing third-party query subtitles: {e}")

    if not subs:
        try:
            resp = session.get(third_party_url, timeout=2.5)
            if resp.status_code == 200:
                html = resp.text
                matches = re.findall(
                    r'["\']?(file|src|kind["\']?\s*:\s*["\']captions["\']?\s*,\s*["\']?file)["\']?\s*:\s*["\'](https?://[^"\']+\.(?:vtt|srt|txt)[^"\']*)["\']',
                    html,
                    re.IGNORECASE
                )
                if not matches:
                    matches = re.findall(r'["\'](https?://[^"\']+\.vtt[^"\']*)["\']', html, re.IGNORECASE)
                
                for idx, match in enumerate(matches):
                    vtt_url = match[1] if isinstance(match, tuple) else match
                    proxy_url = f"/api/sub/decrypt?url={quote_plus(vtt_url)}"
                    subs.append({
                        "language": "English",
                        "code": "en",
                        "decrypted_url": proxy_url,
                        "original_src": vtt_url,
                        "default": idx == 0
                    })
        except Exception as e:
            logging.error(f"Failed scraping embed page subtitles: {e}")

    return subs


def check_m3u8_subtitles(m3u8_url: str) -> List[Dict[str, Any]]:
    """Inspects primary M3U8 master playlist & derived CDN sidecar paths for subtitles."""
    subs = []
    if not m3u8_url:
        return subs

    session = create_session("https://kisskh.do/")

    # 1. Check HLS Subtitle tags (#EXT-X-MEDIA:TYPE=SUBTITLES)
    master_m3u8 = re.sub(r'\.v\d+_index\.m3u8$', '.m3u8', m3u8_url)
    m3u8_targets = [m3u8_url]
    if master_m3u8 != m3u8_url:
        m3u8_targets.insert(0, master_m3u8)

    for m_url in m3u8_targets:
        try:
            resp = session.get(m_url, timeout=2)
            if resp.status_code == 200 and '#EXT-X-MEDIA:TYPE=SUBTITLES' in resp.text:
                for line in resp.text.splitlines():
                    if line.startswith('#EXT-X-MEDIA:TYPE=SUBTITLES'):
                        name_match = re.search(r'NAME="([^"]+)"', line)
                        uri_match = re.search(r'URI="([^"]+)"', line)
                        lang_name = name_match.group(1) if name_match else "English"
                        sub_uri = uri_match.group(1) if uri_match else ""

                        if sub_uri:
                            if not sub_uri.startswith('http'):
                                base_part = m_url.rsplit('/', 1)[0]
                                sub_uri = f"{base_part}/{sub_uri}"
                            
                            raw_lang = lang_name.lower().strip()
                            clean_lang = LANG_MAP.get(raw_lang, lang_name)
                            subs.append({
                                "language": clean_lang,
                                "code": raw_lang[:2],
                                "decrypted_url": f"/api/sub/decrypt?url={quote_plus(sub_uri)}",
                                "original_src": sub_uri,
                                "default": len(subs) == 0
                            })
                if subs:
                    return subs
        except Exception as e:
            logging.debug(f"M3U8 playlist parse failed for {m_url}: {e}")

    # 2. Derive CDN Sidecar Paths (Stripping /hlsXX/ segments)
    parsed_m3u8 = urlparse(m3u8_url)
    sub_host = parsed_m3u8.netloc.replace("hls.", "sub.")
    
    clean_path = re.sub(r'^/hls\d+/', '/', parsed_m3u8.path)
    base_path = re.sub(r'(\.v\d+)?_index\.m3u8$', '', clean_path)
    base_path_no_ext = re.sub(r'\.m3u8$', '', base_path)

    extensions = ['.txt', '.txt1', '.vtt', '.srt', '_en.srt', '_sub.txt']
    possible_vtt_urls = []

    hosts = [sub_host] if sub_host != parsed_m3u8.netloc else []
    hosts.append(parsed_m3u8.netloc)

    for host in hosts:
        for ext in extensions:
            possible_vtt_urls.append(f"{parsed_m3u8.scheme}://{host}{base_path_no_ext}{ext}")
            possible_vtt_urls.append(f"{parsed_m3u8.scheme}://{host}/sub{base_path_no_ext}{ext}")

    seen = set()
    deduped_candidates = [x for x in possible_vtt_urls if not (x in seen or seen.add(x))]

    for vtt_candidate in deduped_candidates[:6]:  # Limit candidates to stay within serverless limits
        try:
            v_resp = session.get(vtt_candidate, timeout=1.5, stream=True)
            if v_resp.status_code in (200, 206):
                content_sample = v_resp.raw.read(100).decode('utf-8', errors='ignore').lower()
                if "<html" not in content_sample and "<!doctype" not in content_sample:
                    subs.append({
                        "language": "English",
                        "code": "en",
                        "decrypted_url": f"/api/sub/decrypt?url={quote_plus(vtt_candidate)}",
                        "original_src": vtt_candidate,
                        "default": True
                    })
                    return subs
        except Exception:
            continue

    return subs


def fetch_kisskh_page_subtitles(drama_id: Optional[str], episode_id: str, video_url: Optional[str] = None) -> List[Dict[str, Any]]:
    """Probes KissKH Subtitle CDN paths directly for encrypted .txt/.txt1 files."""
    subtitles = []
    if not drama_id and not video_url:
        return subtitles

    session = create_session("https://kisskh.do/")

    sub_host = "sub.cdnvideo11.shop"
    if video_url:
        parsed = urlparse(video_url)
        sub_host = parsed.netloc.replace("hls.", "sub.")

    ep_num = "1"
    if video_url:
        ep_match = re.search(r'Ep(\d+)', video_url, re.IGNORECASE)
        if ep_match:
            ep_num = ep_match.group(1)

    extensions = ['.txt', '.txt1', '.vtt', '.srt', '_en.srt']
    possible_sub_urls = []

    if drama_id:
        for ext in extensions:
            possible_sub_urls.extend([
                f"https://{sub_host}/sub/{drama_id}/{episode_id}{ext}",
                f"https://{sub_host}/sub/{drama_id}/Ep{ep_num}{ext}",
                f"https://{sub_host}/auto_upload/{drama_id}/{episode_id}{ext}",
            ])

    seen = set()
    deduped = [x for x in possible_sub_urls if not (x in seen or seen.add(x))]

    for candidate_url in deduped:
        try:
            resp = session.get(candidate_url, timeout=1.5, stream=True)
            if resp.status_code in (200, 206):
                content_sample = resp.raw.read(100).decode('utf-8', errors='ignore').lower()
                if "<html" not in content_sample and "<!doctype" not in content_sample:
                    subtitles.append({
                        "code": "en",
                        "language": "English",
                        "original_src": candidate_url,
                        "decrypted_url": f"/api/sub/decrypt?url={quote_plus(candidate_url)}",
                        "default": True
                    })
                    break
        except Exception:
            continue

    return subtitles


def extract_stream_for_episode(target_id: str, drama_id: Optional[str] = None, title: Optional[str] = None, ep_num: str = "1") -> Dict[str, Any]:
    token = generate_kkey(target_id)
    
    video_data = {}
    video_status = "unknown"
    formatted_subtitles = []
    sub_status = "unknown"

    for base_domain in DOMAINS:
        referer_url = f"{base_domain}/Drama?id={drama_id}" if drama_id else f"{base_domain}/"
        session = create_session(referer_url)

        if not video_data:
            stream_api_url = f"{base_domain}/api/DramaList/Episode/{target_id}.png?err=false&ts=null&time=null&kkey={token}"
            try:
                v_resp = session.get(stream_api_url, timeout=2.5)
                if v_resp.status_code == 200:
                    video_data = v_resp.json()
                    video_status = "200"
                else:
                    video_status = f"HTTP {v_resp.status_code}"
            except Exception as e:
                video_status = f"Error: {str(e)}"

        sub_urls_to_try = [
            f"{base_domain}/api/Sub/{target_id}",
            f"{base_domain}/api/Sub?ep_id={target_id}"
        ]
        
        for sub_api_url in sub_urls_to_try:
            try:
                sub_resp = session.get(sub_api_url, timeout=2)
                
                if sub_resp.status_code == 200:
                    raw_subs = sub_resp.json()
                    
                    if isinstance(raw_subs, dict):
                        raw_subs = raw_subs.get("subtitles") or raw_subs.get("subs") or raw_subs.get("data") or []

                    if isinstance(raw_subs, list) and len(raw_subs) > 0:
                        sub_status = f"200 from {base_domain} (Found {len(raw_subs)} native subs)"
                        
                        for sub in raw_subs:
                            if not isinstance(sub, dict):
                                continue

                            raw_lang = str(sub.get('land') or sub.get('lang') or sub.get('label') or '').lower().strip()
                            clean_lang = LANG_MAP.get(raw_lang, raw_lang.capitalize() or 'Unknown')
                            
                            raw_src = sub.get('src') or sub.get('url') or sub.get('file') or ''
                            
                            if raw_src:
                                if raw_src.startswith('/'):
                                    raw_src = f"{base_domain}{raw_src}"

                                proxy_url = f"/api/sub/decrypt?url={quote_plus(raw_src)}"
                                formatted_subtitles.append({
                                    "language": clean_lang,
                                    "code": raw_lang,
                                    "decrypted_url": proxy_url,
                                    "original_src": raw_src,
                                    "default": bool(sub.get('default', False))
                                })
                        
                        if formatted_subtitles:
                            break
                    else:
                        sub_status = "200 OK (Empty native array or unrecognized format)"
                elif sub_resp.status_code == 404:
                    sub_status = f"404: No native subtitles for episode {target_id}"
                else:
                    sub_status = f"HTTP {sub_resp.status_code} ({base_domain})"
            except Exception as e:
                sub_status = f"Error on {base_domain}: {str(e)}"

        if formatted_subtitles:
            break

    # Tiered Fallback Cascade for Subtitles
    primary_m3u8 = video_data.get("Video")
    if not formatted_subtitles and primary_m3u8:
        m3u8_subs = check_m3u8_subtitles(primary_m3u8)
        if m3u8_subs:
            formatted_subtitles = m3u8_subs
            sub_status += f" -> Extracted {len(m3u8_subs)} sub(s) from CDN video stream"

    if not formatted_subtitles:
        gas_subs = fetch_subtitles_from_gas(target_id)
        if gas_subs:
            formatted_subtitles = gas_subs
            sub_status += f" -> Extracted {len(gas_subs)} sub(s) via Google Apps Script Proxy"

    third_party_url = video_data.get("ThirdParty")
    if not formatted_subtitles and third_party_url:
        tp_subs = extract_third_party_subtitles(third_party_url)
        if tp_subs:
            formatted_subtitles = tp_subs
            sub_status += f" -> Extracted {len(tp_subs)} sub(s) from third_party embed"

    if not formatted_subtitles:
        page_subs = fetch_kisskh_page_subtitles(
            drama_id=drama_id,
            episode_id=target_id,
            video_url=primary_m3u8
        )
        if page_subs:
            formatted_subtitles = page_subs
            sub_status += f" -> Extracted {len(page_subs)} sub(s) via KissKH Page/CDN Extractor"

    if not formatted_subtitles and title:
        ext_subs = fetch_stremio_subtitles(title=title, episode_num=ep_num)
        if ext_subs:
            formatted_subtitles = ext_subs
            sub_status += f" -> Extracted {len(ext_subs)} sub(s) via OpenSubtitles/YaStream Stremio Addons"

    return {
        "status": "success",
        "episode_id": target_id,
        "stream": {
            "primary": primary_m3u8,
            "third_party": third_party_url
        },
        "subtitles": formatted_subtitles,
        "debug": {
            "video_api_status": video_status,
            "sub_api_status": sub_status
        }
    }


# -----------------------------------------------------------------------------
# API ROUTES (STACKED DECORATORS SOLVE VERCEL 404 PATH STRIPPING)
# -----------------------------------------------------------------------------
@app.route('/', methods=['GET'])
@app.route('/api', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "KissKH API is operational on Vercel"}), 200


@app.route('/sub/decrypt', methods=['GET'])
@app.route('/api/sub/decrypt', methods=['GET'])
def decrypt_sub():
    sub_url = request.args.get('url')
    if not sub_url:
        return jsonify({"status": "error", "message": "Missing 'url' parameter"}), 400

    if not is_valid_url(sub_url):
        return jsonify({"status": "error", "message": "Invalid subtitle URL provided"}), 400

    try:
        session = create_session("https://kisskh.do/")
        resp = session.get(sub_url, timeout=3)
        if resp.status_code != 200:
            return jsonify({"status": "error", "message": f"Failed downloading subtitle file (HTTP {resp.status_code})"}), 500

        raw_bytes = resp.content

        if raw_bytes[:2] == b'\x1f\x8b':
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception:
                pass

        try:
            text_content = raw_bytes.decode('utf-8')
            if "WEBVTT" in text_content or "-->" in text_content:
                vtt_text = format_to_vtt(text_content)
                return Response(vtt_text, mimetype='text/vtt')
        except UnicodeDecodeError:
            pass

        decrypted_text = decrypt_subtitle_bytes(raw_bytes, sub_url)
        vtt_text = format_to_vtt(decrypted_text)
        return Response(vtt_text, mimetype='text/vtt')
    except Exception as e:
        return jsonify({"status": "error", "message": f"Subtitle processing failed: {str(e)}"}), 500


@app.route('/extract', methods=['GET'])
@app.route('/api/extract', methods=['GET'])
def extract():
    url = request.args.get('url')
    ep_id = request.args.get('ep_id')
    drama_id = request.args.get('drama_id')
    title = request.args.get('title')

    target_id = ep_id
    if url:
        if not target_id:
            ep_match = re.search(r'ep=(\d+)', url)
            if ep_match:
                target_id = ep_match.group(1)
        if not drama_id:
            drama_match = re.search(r'id=(\d+)', url)
            if drama_match:
                drama_id = drama_match.group(1)

    if not target_id:
        return jsonify({"status": "error", "message": "Must provide 'ep_id' or valid KissKH 'url'"}), 400

    return jsonify(extract_stream_for_episode(target_id, drama_id=drama_id, title=title))


@app.route('/resolve', methods=['GET'])
@app.route('/api/resolve', methods=['GET'])
def resolve():
    raw_title = request.args.get('title', '')
    ep_num = request.args.get('episode', '1')

    if not raw_title:
        return jsonify({"status": "error", "message": "Missing 'title' query parameter"}), 400

    query_title = sanitize_title(raw_title)

    dramas = []
    for domain in DOMAINS:
        search_url = f"{domain}/api/DramaList/Search?q={quote_plus(query_title)}"
        try:
            search_resp = create_session(domain).get(search_url, timeout=2.5)
            if search_resp.status_code == 200 and search_resp.json():
                dramas = search_resp.json()
                break
        except Exception:
            continue

    if not dramas:
        base_title = re.sub(r'(?i)\bseason\s*\d+\b', '', query_title).strip()
        if base_title != query_title:
            for domain in DOMAINS:
                fallback_url = f"{domain}/api/DramaList/Search?q={quote_plus(base_title)}"
                try:
                    fallback_resp = create_session(domain).get(fallback_url, timeout=2.5)
                    if fallback_resp.status_code == 200 and fallback_resp.json():
                        dramas = fallback_resp.json()
                        break
                except Exception:
                    pass

    if not dramas:
        return jsonify({"status": "error", "message": f"No drama found matching '{query_title}'"}), 404

    target_drama = None
    query_lower = query_title.lower()

    for d in dramas:
        if d.get('title', '').lower() == query_lower:
            target_drama = d
            break

    if not target_drama:
        query_words = set(re.findall(r'\w+', query_lower))
        for d in dramas:
            d_title_words = set(re.findall(r'\w+', d.get('title', '').lower()))
            if query_words.issubset(d_title_words):
                target_drama = d
                break

    if not target_drama:
        for d in dramas:
            d_title = d.get('title', '').lower()
            if query_lower in d_title:
                target_drama = d
                break

    if not target_drama:
        available_titles = [d.get('title') for d in dramas[:5]]
        return jsonify({
            "status": "error", 
            "message": f"Could not confidently match '{query_title}'.",
            "close_matches": available_titles
        }), 404

    drama_id = target_drama.get('id')

    episodes = []
    for domain in DOMAINS:
        drama_detail_url = f"{domain}/api/DramaList/Drama/{drama_id}"
        try:
            detail_resp = create_session(domain).get(drama_detail_url, timeout=2.5)
            if detail_resp.status_code == 200:
                episodes = detail_resp.json().get('episodes', [])
                break
        except Exception:
            continue

    if not episodes:
        return jsonify({"status": "error", "message": "Failed to fetch drama episode list"}), 500

    try:
        target_num = float(ep_num)
    except ValueError:
        target_num = None

    target_ep = None
    for ep in episodes:
        num = ep.get('number')
        if target_num is not None and num is not None:
            try:
                if float(num) == target_num:
                    target_ep = ep
                    break
            except (ValueError, TypeError):
                pass
        if str(num).strip() == str(ep_num).strip():
            target_ep = ep
            break

    if not target_ep:
        available_eps = [ep.get('number') for ep in episodes]
        return jsonify({
            "status": "error", 
            "message": f"Episode {ep_num} not found for '{target_drama.get('title')}'",
            "available_episodes": available_eps
        }), 404

    episode_id = str(target_ep.get('id'))
    resolved_title = target_drama.get('title')

    res = extract_stream_for_episode(episode_id, drama_id=str(drama_id), title=resolved_title, ep_num=ep_num)
    res["resolved_drama_id"] = drama_id
    res["resolved_title"] = resolved_title
    return jsonify(res)


if __name__ == '__main__':
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    app.run(host=host, port=port)
