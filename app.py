import re
import json
import base64
import time
from typing import List, Dict, Optional, Union, Any
from urllib.parse import urlparse, urljoin, quote
import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request, render_template, abort, Response
from flask_cors import CORS
import asyncio
import httpx
from datetime import datetime, timedelta, timezone
import pytz
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad
from tznn import tznn


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
    if MD5 is None: raise ImportError("pycryptodome is required for decryption.")
    derived_bytes = b''
    block = b''
    while len(derived_bytes) < key_len + iv_len:
        hasher = MD5.new()
        if block: hasher.update(block)
        hasher.update(password)
        hasher.update(salt)
        block = hasher.digest()
        derived_bytes += block
    return derived_bytes[:key_len], derived_bytes[key_len:key_len + iv_len]

def decrypt_cryptojs_aes(encrypted_b64: str, passphrase_str: str) -> str:
    if AES is None or unpad is None: raise ImportError("pycryptodome is required for decryption.")
    passphrase_bytes = passphrase_str.encode('utf-8')
    encrypted_data_bytes = base64.b64decode(encrypted_b64)
    if not encrypted_data_bytes.startswith(b"Salted__"):
        try:
            key = bytes.fromhex(passphrase_str)
            iv = encrypted_data_bytes[:16]
            actual_ciphertext = encrypted_data_bytes[16:]
            if len(key) != 32: raise ValueError("Direct key is not 32 bytes for AES-256.")
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(actual_ciphertext)
            decrypted = unpad(decrypted_padded, AES.block_size, style='pkcs7')
            return decrypted.decode('utf-8')
        except Exception:
            raise ValueError("Ciphertext not in OpenSSL salted format and direct key decryption failed.")

    salt = encrypted_data_bytes[8:16]
    actual_ciphertext = encrypted_data_bytes[16:]
    key, iv = evp_bytes_to_key(passphrase_bytes, salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(actual_ciphertext)
    try:
        decrypted = unpad(decrypted_padded, AES.block_size, style='pkcs7')
    except ValueError as e:
        raise ValueError(f"Failed to unpad data. Error: {e}") from e
    return decrypted.decode('utf-8')


class IAnimeResult:
    def __init__(self, data: Dict):
        self.id = data.get('id', '')
        self.title = data.get('title', '')
        self.image = data.get('image', '')
        self.url = data.get('url', '')
        self.japanese_title = data.get('japanese_title', '')
        self.type = data.get('type', '')
        self.duration = data.get('duration', '')
        self.sub = data.get('sub', 0)
        self.dub = data.get('dub', 0)
        self.episodes = data.get('episodes', 0)
        self.nsfw = data.get('nsfw', False)
        self.other_data = data.get('other_data', {})


class IAnimeEpisode:
    def __init__(self, data: Dict):
        self.id = data.get('id', '')
        self.number = data.get('number', 0)
        self.title = data.get('title', '')
        self.is_filler = data.get('is_filler', False)
        self.is_subbed = data.get('is_subbed', False)
        self.is_dubbed = data.get('is_dubbed', False)
        self.url = data.get('url', '')

class ISource:
    def __init__(self):
        self.headers: Dict[str, str] = {}
        self.sources: List[Dict[str, Any]] = []
        self.subtitles: List[Dict[str, str]] = []
        self.previews: List[Dict[str, str]] = []

class IAnimeInfo:
    def __init__(self):
        self.id = ''
        self.title = ''
        self.japanese_title = ''
        self.image = ''
        self.cover = ''
        self.description = ''
        self.type = ''
        self.status = ''
        self.genres: List[str] = []
        self.aired: str = ''
        self.premiered: str = ''
        self.duration: str = ''
        self.mal_score: str = ''
        self.studios: List[str] = []
        self.producers: List[str] = []
        self.episodes: List[IAnimeEpisode] = []
        self.total_episodes = 0
        self.mal_id: Optional[int] = None
        self.anilist_id: Optional[int] = None
        self.url = ''
        self.sub = 0
        self.dub = 0
        self.recommendations: List[IAnimeResult] = []
        self.has_dub = False
        self.has_sub = False
        self.sub_or_dub = "sub"

class Zoro:
    SERVER_NAME_TO_DATA_SERVER_ID = {
        "vidcloud": "1", "megacloud": "1", "upcloud": "6",
        "streamvid": "4", "vidstreaming": "4",
        "streamsb": "5", "watchsb": "5", "streamtape": "3",
    }
    MEGA_CLOUD_KEY_URL = "https://raw.githubusercontent.com/carlosesteven/e1-player-deobf/main/output/key.json"
    _megacloud_key_cache: Optional[str] = None
    _megacloud_key_last_fetch: float = 0
    _megacloud_key_cache_ttl: int = 3600

    def __init__(self, custom_base_url:Optional[str]=None):
        self.name = 'HiAnime'
        self.base_url = 'https://hianime.to'
        self.logo = 'https://is3-ssl.mzstatic.com/image/thumb/Purple112/v4/7e/91/00/7e9100ee-2b62-0942-4cdc-e9b93252ce1c/source/512x512bb.jpg'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        if custom_base_url:
            self.base_url = custom_base_url.rstrip('/') if custom_base_url.startswith(('http://', 'https://')) else f'https://{custom_base_url.rstrip("/")}'

    def _fetch_megacloud_key(self) -> str:
        current_time = time.time()
        if self._megacloud_key_cache and (current_time - self._megacloud_key_last_fetch < self._megacloud_key_cache_ttl):
            return self._megacloud_key_cache
        try:
            key_url_with_ts = f"{self.MEGA_CLOUD_KEY_URL}?v={int(current_time)}"
            response = self.session.get(key_url_with_ts, timeout=10)
            response.raise_for_status()
            key_data = response.json()
            decrypt_key = key_data.get("decryptKey")
            if not decrypt_key or not isinstance(decrypt_key, str):
                raise ValueError("Decrypt key not found or invalid in fetched data.")
            self._megacloud_key_cache = decrypt_key
            self._megacloud_key_last_fetch = current_time
            return decrypt_key
        except Exception as e:
            raise Exception(f"Could not fetch or validate MegaCloud decryption key: {e}")

    def search(self, query: str, page: int = 1) -> Dict[str, Union[bool, List[IAnimeResult], int]]:
        if page <= 0: page = 1
        url = f"{self.base_url}/search?keyword={quote(query)}&page={page}"
        return self._scrape_card_page(url)

    def fetch_anime_info(self, anime_id: str) -> IAnimeInfo:
        info = IAnimeInfo()
        info.id = anime_id
        anime_url = f"{self.base_url}/{anime_id}"
        try:
            response = self.session.get(anime_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            sync_data_script = soup.find('script', id='syncData')
            if sync_data_script and sync_data_script.string:
                try:
                    data = json.loads(sync_data_script.string)
                    info.mal_id = data.get('mal_id')
                    info.anilist_id = data.get('anilist_id')
                except json.JSONDecodeError:
                    pass

            title_elem = soup.select_one('h2.film-name')
            if title_elem:
                info.title = title_elem.text.strip()

            film_stats_div = soup.select_one('div.film-stats')
            if film_stats_div:
                type_elem = film_stats_div.select_one('span.item')
                duration_elem = film_stats_div.select('span.item')[-1]
                if type_elem:
                    info.type = type_elem.text.strip().upper()
                if duration_elem and "m" in duration_elem.text:
                    info.duration = duration_elem.text.strip()

            anisc_info_div = soup.select_one('div.anisc-info')
            if anisc_info_div:
                for item_div in anisc_info_div.select('.item.item-title, .item.item-list'):
                    item_head_elem = item_div.select_one('.item-head')
                    if not item_head_elem:
                        continue

                    key = item_head_elem.text.strip().lower().replace(':', '')
                    value_elems = item_div.select('a.name, span.name')
                    
                    if key == "japanese":
                        info.japanese_title = value_elems[0].text.strip() if value_elems else ''
                    elif key == "aired":
                        info.aired = value_elems[0].text.strip() if value_elems else ''
                    elif key == "premiered":
                        info.premiered = value_elems[0].text.strip() if value_elems else ''
                    elif key == "duration" and not info.duration:
                        info.duration = value_elems[0].text.strip() if value_elems else ''
                    elif key == "status":
                        status_text = value_elems[0].text.strip() if value_elems else ''
                        if 'Finished' in status_text or 'Completed' in status_text:
                            info.status = 'COMPLETED'
                        elif 'Airing' in status_text:
                            info.status = 'ONGOING'
                        else:
                            info.status = 'UNKNOWN'
                    elif key == "mal score":
                        info.mal_score = value_elems[0].text.strip() if value_elems else ''
                    elif key == "genres":
                        info.genres = [elem.text.strip() for elem in item_div.select('a')]
                    elif key == "studios":
                        info.studios = [elem.text.strip() for elem in value_elems]
                    elif key == "producers":
                        info.producers = [elem.text.strip() for elem in value_elems]

            img_elem = soup.select_one('img.film-poster-img')
            if img_elem:
                info.image = img_elem.get('src', '')
            
            cover_style = soup.select_one('.film-cover')['style'] if soup.select_one('.film-cover') else None
            if cover_style:
                info.cover = re.search(r"url\('(.*?)'\)", cover_style).group(1)
            
            desc_elem = soup.select_one('div.film-description div.text')
            if desc_elem:
                info.description = desc_elem.text.strip()

            sub_elem = soup.select_one('div.film-stats div.tick div.tick-item.tick-sub')
            dub_elem = soup.select_one('div.film-stats div.tick div.tick-item.tick-dub')
            
            info.sub = int(sub_elem.text.strip()) if sub_elem and sub_elem.text.strip().isdigit() else 0
            info.dub = int(dub_elem.text.strip()) if dub_elem and dub_elem.text.strip().isdigit() else 0
            info.has_sub = info.sub > 0
            info.has_dub = info.dub > 0
            
            if info.has_sub and info.has_dub:
                info.sub_or_dub = "both"
            elif info.has_dub:
                info.sub_or_dub = "dub"
            else:
                info.sub_or_dub = "sub"

            info.recommendations = []
            related_section = soup.select_one('.block_area-content .anif-block-ul')
            if related_section:
                for item in related_section.select('li'):
                    title_elem = item.select_one('h3.film-name a')
                    if not title_elem:
                        continue
                    
                    anime_id = title_elem['href'].strip('/')
                    image_elem = item.select_one('img.film-poster-img')
                    
                    type_elem = item.select_one('.tick')
                    anime_type = None
                    if type_elem:
                        type_text = type_elem.text.strip()
                        if 'TV' in type_text:
                            anime_type = 'TV'
                        elif 'Movie' in type_text:
                            anime_type = 'MOVIE'
                        elif 'ONA' in type_text:
                            anime_type = 'ONA'
                    
                    info.recommendations.append(IAnimeResult({
                        'id': anime_id,
                        'title': title_elem.get('title') or title_elem.text.strip(),
                        'image': image_elem.get('data-src') or image_elem.get('src', ''),
                        'url': urljoin(self.base_url, title_elem['href']),
                        'type': anime_type
                    }))

            ajax_id_elem = soup.select_one("div#wrapper[data-id]")
            ajax_episode_id = ajax_id_elem['data-id'] if ajax_id_elem else anime_id.split('-')[-1]
            if not ajax_episode_id:
                raise Exception("Could not find AJAX episode ID")

            episodes_ajax_url = f"{self.base_url}/ajax/v2/episode/list/{ajax_episode_id}"
            episodes_response = self.session.get(
                episodes_ajax_url,
                headers={
                    'X-Requested-With': 'XMLHttpRequest',
                    'Referer': anime_url
                }
            )
            episodes_response.raise_for_status()
            episodes_data = episodes_response.json()

            if 'html' in episodes_data:
                episodes_soup = BeautifulSoup(episodes_data['html'], 'html.parser')
                for ep_elem in episodes_soup.select('div.ss-list a.ssl-item.ep-item'):
                    ep_href = ep_elem.get('href', '')
                    if not ep_href:
                        continue
                    parsed_href = urlparse(ep_href)
                    actual_ep_id_for_source = re.search(r'ep=(\d+)', parsed_href.query).group(1)
                    if not actual_ep_id_for_source:
                        continue

                    class_ep_id = f"{anime_id}$episode${actual_ep_id_for_source}"
                    ep_number = int(ep_elem.get('data-number', '0'))
                    ep_title = ep_elem.get('title', f"Episode {ep_number}")
                    info.episodes.append(IAnimeEpisode({
                        'id': class_ep_id,
                        'number': ep_number,
                        'title': ep_title,
                        'is_filler': 'filler' in ep_elem.get('class', []),
                        'url': urljoin(self.base_url, ep_href),
                        'is_subbed': ep_number <= info.sub,
                        'is_dubbed': ep_number <= info.dub
                    }))
                info.total_episodes = len(info.episodes)
            
            info.url = anime_url
            return info
        except Exception as e:
            raise Exception(f"Failed to fetch anime info for {anime_id}: {e}")

    @staticmethod
    async def get_client_key(embed_url: str) -> str:
        headers = {
            "Referer": "https://hianime.to",
            "User-Agent": "Mozilla/5.0"
        }

        async with httpx.AsyncClient() as client:
            for i in range(5):
                try:
                    response = await client.get(embed_url, headers=headers)
                    html = response.text
                    soup = BeautifulSoup(html, "html.parser")

                    meta = soup.find("meta", attrs={"name": "_gg_fb"})
                    if meta and meta.get("content"):
                        return meta["content"]

                    comment_matches = re.findall(r"<!--\s*(_is_th:[^>]+?)\s*-->", html)
                    for comment in comment_matches:
                        match = re.match(r"_is_th:([^\n\r]+)", comment)
                        if match:
                            return match.group(1).strip()

                    dpi_div = soup.find(attrs={"data-dpi": True})
                    if dpi_div:
                        return dpi_div["data-dpi"]

                    scripts = soup.find_all("script")
                    for script in scripts:
                        script_text = script.text.strip()
                        xy_match = re.search(r'window\._xy_ws\s*=\s*[\'"]([^\'"]+)[\'"]', script_text)
                        if xy_match:
                            return xy_match.group(1)

                        lk_match = re.search(
                            r'window\._lk_db\s*=\s*{x:\s*[\'"]([^\'"]+)[\'"],\s*y:\s*[\'"]([^\'"]+)[\'"],\s*z:\s*[\'"]([^\'"]+)[\'"]}',
                            script_text
                        )
                        if lk_match:
                            return lk_match.group(1) + lk_match.group(2) + lk_match.group(3)

                except Exception:
                    continue
        return None


    def _extract_vidcloud_sources(self, embed_url: str, referer: str, ep_site_id: str, audio_type: str) -> ISource:
        source_obj = ISource()
        primary_data = None

        try:
            embed_host = urlparse(embed_url).netloc
            video_id = embed_url.split('/')[-1].split('?')[0]
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            key = loop.run_until_complete(Zoro.get_client_key(embed_url))

            if not key:
                raise Exception("No client key found for embed URL.")

            ajax_sources_url = f"https://{embed_host}/embed-2/v3/e-1/getSources?id={video_id}&_k={key}"
            ajax_response = self.session.get(
                ajax_sources_url,
                headers={'X-Requested-With': 'XMLHttpRequest', 'Referer': referer}
            )
            ajax_response.raise_for_status()
            primary_data = ajax_response.json()

            decrypted_sources_list = []
            passphrase = self._fetch_megacloud_key()
            if primary_data.get('encrypted') and isinstance(primary_data.get('sources'), str):
                decrypted_json_str = decrypt_cryptojs_aes(primary_data['sources'], passphrase)
                decrypted_sources_list = json.loads(decrypted_json_str)
            elif isinstance(primary_data.get('sources'), list):
                decrypted_sources_list = primary_data['sources']

            if decrypted_sources_list:
                source_obj.sources.append({
                    'url': decrypted_sources_list[0]['file'],
                    'quality': 'auto',
                    'isM3U8': True
                })
                source_obj.headers['Referer'] = embed_url
                source_obj.subtitles = [
                    {'url': t['file'], 'lang': t.get('label', 'Default')}
                    for t in primary_data.get('tracks', []) if t.get('kind') in ['captions', 'subtitles']
                ]
                source_obj.previews = [
                    {'url': t['file'], 'type': 'vtt'}
                    for t in primary_data.get('tracks', []) if t.get('kind') == 'thumbnails'
                ]
                source_obj.intro = primary_data.get('intro') or {'start': 0, 'end': 0}
                source_obj.outro = primary_data.get('outro') or {'start': 0, 'end': 0}
                return source_obj

            raise Exception("No sources available from primary method.")

        except Exception as e:
            try:
                yuma_api_url = f"https://yumaapisources.vercel.app/sources?url={embed_url}"
                yuma_response = self.session.get(yuma_api_url)
                yuma_response.raise_for_status()
                yuma_data = yuma_response.json()

                if yuma_data.get('sources'):
                    source_obj.sources = [{'url': s['file'], 'quality': s['quality'], 'isM3U8': True, 'type': s.get('type')} for s in yuma_data['sources']]
                    source_obj.headers['Referer'] = embed_url

                    source_obj.subtitles = []
                    for track in yuma_data.get('tracks', []):
                        if track.get('kind') in ['subtitles', 'captions']:
                            source_obj.subtitles.append({
                                'url': track['file'],
                                'lang': track.get('label', 'Default')
                            })

                    return source_obj
            except Exception as yuma_error:
                try:
                    epID = ep_site_id
                    type_ = audio_type
                    server = 'hd-1'
                    
                    fallback_host = "megaplay.buzz" if server.lower() == 'hd-1' else "vidwish.live"
                    stream_url = f"https://{fallback_host}/stream/s-2/{epID}/{type_}"

                    html_response = self.session.get(stream_url, headers={'Referer': f"https://{fallback_host}/"})
                    html_response.raise_for_status()
                    html = html_response.text

                    match = re.search(r'data-id=["\'](\d+)["\']', html)
                    if not match:
                        raise Exception("data-id not found in fallback HTML")
                    real_id = match.group(1)

                    sources_url = f"https://{fallback_host}/stream/getSources"
                    json_response = self.session.get(
                        sources_url, headers={'X-Requested-With': 'XMLHttpRequest'}, params={'id': real_id}
                    )
                    json_response.raise_for_status()
                    fallback_data = json_response.json()

                    file_url = fallback_data.get('sources', {}).get('file')
                    if not file_url:
                        raise Exception("No source file URL found in fallback response.")

                    source_obj.sources.append({
                        'url': file_url,
                        'quality': 'AUTO',
                        'isM3U8': True,
                        'type': 'hls'
                    })
                    source_obj.headers['Referer'] = stream_url

                    if primary_data and isinstance(primary_data, dict):
                        source_obj.subtitles = [
                            {'url': t['file'], 'lang': t.get('label', 'Default')}
                            for t in primary_data.get('tracks', []) if t.get('kind') in ['captions', 'subtitles']
                        ]
                        source_obj.intro = primary_data.get('intro', {'start': 0, 'end': 0})
                        source_obj.outro = primary_data.get('outro', {'start': 0, 'end': 0})
                    else:
                        source_obj.subtitles = fallback_data.get('tracks', [])
                        source_obj.intro = fallback_data.get('intro', {'start': 0, 'end': 0})
                        source_obj.outro = fallback_data.get('outro', {'start': 0, 'end': 0})
                    
                    return source_obj
                except Exception as fallback_error:
                    raise Exception(f"Primary source extraction failed: [{e}]. Yuma API fallback failed: [{yuma_error}]. Final fallback also failed: [{fallback_error}]")

    def fetch_episode_sources(self, episode_id: str, audio_type: str = "sub", server: str = "vidcloud") -> ISource:
        if '$episode$' not in episode_id:
            raise ValueError("Invalid episode ID format.")
        try:
            anime_slug, ep_site_id = episode_id.split('$episode$')
            referer_url = f"{self.base_url}/watch/{anime_slug}"
            servers_ajax_url = f"{self.base_url}/ajax/v2/episode/servers?episodeId={ep_site_id}"
            
            servers_response = self.session.get(
                servers_ajax_url, headers={'X-Requested-With': 'XMLHttpRequest', 'Referer': referer_url}
            )
            servers_response.raise_for_status()
            servers_soup = BeautifulSoup(servers_response.json()['html'], 'html.parser')

            target_block = servers_soup.select_one(f"div.ps_-block.servers-{audio_type.lower()}")
            if not target_block:
                fallback_audio_type = 'dub' if audio_type.lower() == 'sub' else 'sub'
                target_block = servers_soup.select_one(f"div.ps_-block.servers-{fallback_audio_type}")
                if not target_block:
                    raise Exception(f"Neither {audio_type.upper()} nor {fallback_audio_type.upper()} server blocks found.")

            data_server_id = self.SERVER_NAME_TO_DATA_SERVER_ID.get(server.lower())
            if not data_server_id:
                raise NotImplementedError(f"Server '{server}' is not supported.")

            server_item = target_block.select_one(f".server-item[data-server-id='{data_server_id}']")
            if not server_item:
                server_item = target_block.select_one(".server-item")
                if not server_item:
                    raise Exception(f"Server '{server}' not found and no other servers available for this episode.")

            hianime_server_id = server_item['data-id']
            link_ajax_url = f"{self.base_url}/ajax/v2/episode/sources?id={hianime_server_id}"
            link_response = self.session.get(
                link_ajax_url, headers={'X-Requested-With': 'XMLHttpRequest', 'Referer': referer_url}
            )
            link_response.raise_for_status()
            embed_url = link_response.json().get('link')

            if not embed_url:
                raise Exception("Could not retrieve embed URL.")

            if server.lower() in ["vidcloud", "megacloud"]:
                return self._extract_vidcloud_sources(embed_url, referer_url, ep_site_id, audio_type)
            else:
                raise NotImplementedError(f"Extractor for server '{server}' is not implemented.")

        except Exception as e:
            raise Exception(f"Fetch sources failed for {episode_id}: {e}")
            
    def fetch_recently_updated(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/recently-updated?page={page}")
    def fetch_top_airing(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/top-airing?page={page}")
    def fetch_most_popular(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/most-popular?page={page}")
    def fetch_most_favorite(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/most-favorite?page={page}")
    def fetch_latest_completed(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/completed?page={page}")
    def fetch_recently_added(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/recently-added?page={page}")
    def fetch_top_upcoming(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/top-upcoming?page={page}")
    def fetch_movie(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/movie?page={page}")
    def fetch_tv(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/tv?page={page}")
    def fetch_ova(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/ova?page={page}")
    def fetch_ona(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/ona?page={page}")
    def fetch_special(self, page: int = 1): return self._scrape_card_page(f"{self.base_url}/special?page={page}")
    def genre_search(self, genre: str, page: int = 1): return self._scrape_card_page(f"{self.base_url}/genre/{genre}?page={page}")
    def fetch_studio(self, studio_id: str, page: int = 1): return self._scrape_card_page(f"{self.base_url}/producer/{studio_id}?page={page}")

    def fetch_genres(self) -> List[str]:
        try:
            res = self.session.get(f"{self.base_url}/home")
            res.raise_for_status()
            soup = BeautifulSoup(res.text, 'html.parser')
            genres = [a.text.lower().replace(' ', '-') for a in soup.select('#main-sidebar ul.sb-genre-list li a')]
            return genres
        except Exception as e:
            raise Exception(f"Failed to fetch genres: {e}")

    def fetch_schedule(self, date: str) -> List[IAnimeResult]:
        try:
            ajax_url = f"{self.base_url}/ajax/schedule/list?tzOffset=0&date={date}"
            res = self.session.get(ajax_url)
            res.raise_for_status()
            
            soup = BeautifulSoup(res.json()['html'], 'html.parser')
            initial_results = []
            
            for item in soup.select('li'):
                link_elem = item.select_one('a.tsl-link')
                if not link_elem:
                    continue

                href = link_elem.get('href')
                if not href:
                    continue
                
                anime_id = href.strip('/')
                title_elem = link_elem.select_one('h3.film-name')
                time_elem = link_elem.select_one('div.time')
                episode_button = link_elem.select_one('div.fd-play button')

                result_item = IAnimeResult({
                    'id': anime_id,
                    'title': title_elem.text.strip() if title_elem else '',
                    'japanese_title': title_elem.get('data-jname', '') if title_elem else '',
                    'url': urljoin(self.base_url, href),
                    'type': 'SCHEDULED',
                    'other_data': {
                        'airingTime': time_elem.text.strip() if time_elem else '',
                        'airingEpisode': episode_button.text.strip() if episode_button else ''
                    }
                })
                initial_results.append(result_item)

            hydrated_results = []
            for res_item in initial_results:
                try:
                    anime_info = self.fetch_anime_info(res_item.id)
                    res_item.image = anime_info.image
                except Exception as e:
                    print(f"Could not hydrate image for {res_item.id}: {e}")
                    res_item.image = ''
                
                hydrated_results.append(res_item)

            return hydrated_results
            
        except Exception as e:
            raise Exception(f"Failed to fetch schedule for {date}: {e}")

    def fetch_spotlight(self) -> List[IAnimeResult]:
        try:
            res = self.session.get(f"{self.base_url}/home")
            res.raise_for_status()
            soup = BeautifulSoup(res.text, 'html.parser')
            results = []
            
            for slide in soup.select('#slider .swiper-slide:not(.swiper-slide-duplicate)'):
                detail_link = slide.select_one('.desi-buttons a.btn-secondary')
                if not detail_link or not detail_link.get('href'):
                    continue

                anime_id = detail_link.get('href').strip('/')
                
                title_elem = slide.select_one('.desi-head-title')
                img_elem = slide.select_one('img.film-poster-img')
                description_elem = slide.select_one('.desi-description')
                rank_elem = slide.select_one('.desi-sub-text')
                
                sc_detail = slide.select_one('.sc-detail')
                sc_items = sc_detail.select('.scd-item') if sc_detail else []
                
                anime_type = sc_items[0].text.strip() if len(sc_items) > 0 else "UNKNOWN"
                duration = sc_items[1].text.strip() if len(sc_items) > 1 else ""
                release_date = sc_items[2].text.strip() if len(sc_items) > 2 else ""

                tick_div = slide.select_one('.tick')
                sub_elem = tick_div.select_one('.tick-sub') if tick_div else None
                dub_elem = tick_div.select_one('.tick-dub') if tick_div else None
                eps_elem = tick_div.select_one('.tick-eps') if tick_div else None

                sub_count = int(sub_elem.text.strip()) if sub_elem and sub_elem.text.strip().isdigit() else 0
                dub_count = int(dub_elem.text.strip()) if dub_elem and dub_elem.text.strip().isdigit() else 0
                eps_count = int(eps_elem.text.strip()) if eps_elem and eps_elem.text.strip().isdigit() else 0

                results.append(IAnimeResult({
                    'id': anime_id,
                    'title': title_elem.text.strip() if title_elem else '',
                    'japanese_title': title_elem.get('data-jname', '') if title_elem else '',
                    'image': img_elem.get('data-src') if img_elem else '',
                    'url': urljoin(self.base_url, detail_link['href']),
                    'type': anime_type,
                    'duration': duration,
                    'sub': sub_count,
                    'dub': dub_count,
                    'episodes': eps_count,
                    'other_data': {
                        'description': description_elem.text.strip() if description_elem else '',
                        'rank': rank_elem.text.strip() if rank_elem else '',
                        'releaseDate': release_date,
                    }
                }))
            return results
        except Exception as e:
            raise Exception(f"Failed to fetch spotlight: {e}")

    def fetch_search_suggestions(self, query: str):
        try:
            ajax_url = f"{self.base_url}/ajax/search/suggest?keyword={quote(query)}"
            res = self.session.get(ajax_url)
            res.raise_for_status()

            soup = BeautifulSoup(res.json()['html'], 'html.parser')
            results = []

            for item in soup.select('a.nav-item:not(.nav-bottom)'):
                href = item.get('href')
                if not href:
                    continue

                anime_id = href.strip('/')
                
                title_elem = item.select_one('h3.film-name')
                img_elem = item.select_one('img.film-poster-img')
                film_infor = item.select_one('.film-infor')
                
                title_text = title_elem.text.strip() if title_elem else ''
                japanese_title = title_elem.get('data-jname', '') if title_elem else ''

                release_date_elem = film_infor.select_one('span')
                release_date = release_date_elem.text.strip() if release_date_elem else ''
                
                info_texts = [text.strip() for text in film_infor.find_all(string=True, recursive=False) if text.strip()]
                anime_type = info_texts[0] if info_texts else ''
                
                duration_span = film_infor.select('span')[-1] if film_infor.select('span') else None
                duration = duration_span.text.strip() if duration_span and duration_span != release_date_elem else ''

                results.append(IAnimeResult({
                    'id': anime_id,
                    'title': item.select_one('.alias-name').text.strip() if item.select_one('.alias-name') else title_text,
                    'japanese_title': japanese_title,
                    'image': img_elem.get('data-src') if img_elem else '',
                    'url': urljoin(self.base_url, href),
                    'type': anime_type,
                    'duration': duration,
                    'other_data': {
                       'releaseDate': release_date,
                       'alias': item.select_one('.alias-name').text.strip() if item.select_one('.alias-name') else ''
                    }
                }))
            return results
        except Exception as e:
            raise Exception(f"Failed to fetch search suggestions for '{query}': {e}")
            
    def _scrape_card_page(self, url: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {'current_page': 1, 'has_next_page': False, 'total_pages': 1, 'results': []}
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            pagination = soup.select_one('ul.pagination')
            if pagination:
                active_page = pagination.select_one('.page-item.active a')
                if active_page and active_page.text.strip().isdigit():
                    result['current_page'] = int(active_page.text.strip())
                
                next_page_item = pagination.select_one('li.page-item a[title="Next"]')
                result['has_next_page'] = bool(next_page_item)

                last_page_item = pagination.select_one('li.page-item a[title="Last"]')
                if last_page_item and 'page=' in last_page_item.get('href', ''):
                    last_page_match = re.search(r'page=(\d+)', last_page_item['href'])
                    if last_page_match:
                        result['total_pages'] = int(last_page_match.group(1))
                elif not result['has_next_page']:
                     result['total_pages'] = result['current_page']

            for card in soup.select('div.flw-item'):
                title_elem = card.select_one('h3.film-name a')
                if not title_elem or not title_elem.get('href'):
                    continue

                anime_id = title_elem.get('href').strip('/')

                poster_div = card.select_one('.film-poster')
                detail_div = card.select_one('.film-detail')

                img_elem = poster_div.select_one('img.film-poster-img') if poster_div else None
                
                sub_elem = poster_div.select_one('.tick-item.tick-sub') if poster_div else None
                dub_elem = poster_div.select_one('.tick-item.tick-dub') if poster_div else None
                eps_elem = poster_div.select_one('.tick-item.tick-eps') if poster_div else None

                sub_count = int(sub_elem.text.strip()) if sub_elem and sub_elem.text.strip().isdigit() else 0
                dub_count = int(dub_elem.text.strip()) if dub_elem and dub_elem.text.strip().isdigit() else 0
                eps_count_elem = poster_div.select_one('.tick-item.tick-eps') if poster_div else None

                if eps_count_elem and eps_count_elem.text.strip().isdigit():
                    eps_count = int(eps_count_elem.text.strip())
                else:
                    eps_count = max(sub_count, dub_count)

                fdi_items = detail_div.select('.fd-infor .fdi-item') if detail_div else []
                anime_type = fdi_items[0].text.strip() if fdi_items else "UNKNOWN"
                duration = fdi_items[1].text.strip() if len(fdi_items) > 1 else ""

                result['results'].append(IAnimeResult({
                    'id': anime_id,
                    'title': title_elem.get('title', ''),
                    'url': urljoin(self.base_url, title_elem['href']),
                    'image': img_elem.get('data-src', '') if img_elem else '',
                    'japanese_title': title_elem.get('data-jname', ''),
                    'type': anime_type,
                    'duration': duration,
                    'sub': sub_count,
                    'dub': dub_count,
                    'episodes': eps_count,
                    'nsfw': bool(poster_div.select_one('.tick-rate[title="18+"]')) if poster_div else False
                }))
            return result
        except Exception as e:
            raise Exception(f"Failed to scrape page {url}: {e}")

app = Flask(__name__, template_folder='templates')
CORS(app, origins="*")
zoro = Zoro()

def to_dict_list(data_list):
    return [item.__dict__ for item in data_list]

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, requests.HTTPError):
        return jsonify(error=f"Upstream provider error: {e.response.status_code}"), e.response.status_code
    if isinstance(e, NotImplementedError):
        return jsonify(error=f"Not Implemented: {str(e)}"), 501
    
    app.logger.error(f"Unhandled Exception: {e}", exc_info=True)
    return jsonify(error=f"An internal error occurred: {str(e)}"), 500

@app.route("/")
def home():
    return render_template('docs.html')

@app.route("/docs")
def docs():
    return render_template('docs.html')

@app.route("/search/<query>")
def search(query):
    page = request.args.get('page', default=1, type=int)
    max_results = request.args.get('max_results', default=None, type=int)

    results = zoro.search(query, page)
    results['results'] = to_dict_list(results['results'])

    for item in results['results']:
        if item.get('id'):
            item['id'] = item['id'].replace('?ref=search', '')
        if item.get('url'):
            item['url'] = item['url'].replace('?ref=search', '')

    if max_results is not None:
        results['results'] = results['results'][:max_results]

    return jsonify(results)

@app.route("/info/<anime_id>")
def info(anime_id):
    result = zoro.fetch_anime_info(anime_id)
    result_dict = result.__dict__
    result_dict['episodes'] = to_dict_list(result.episodes)
    result_dict['recommendations'] = to_dict_list(result.recommendations)
    return jsonify(result_dict)

@app.route("/watch")
def watch():
    episode_id = request.args.get('episodeId', type=str)
    audio_type = request.args.get('type', default='sub', type=str)
    server = request.args.get('server', default='vidcloud', type=str)
    if not episode_id:
        abort(400, description="episodeId is a required query parameter.")
    
    sources = zoro.fetch_episode_sources(episode_id, audio_type, server)
    return jsonify(sources.__dict__)

def create_card_page_route(func_name):
    def route():
        page = request.args.get('page', default=1, type=int)
        func = getattr(zoro, func_name)
        data = func(page)
        data['results'] = to_dict_list(data['results'])
        return jsonify(data)
    return route

app.add_url_rule('/recent-episodes', 'recent-episodes', create_card_page_route('fetch_recently_updated'))
app.add_url_rule('/top-airing', 'top-airing', create_card_page_route('fetch_top_airing'))
app.add_url_rule('/most-popular', 'most-popular', create_card_page_route('fetch_most_popular'))
app.add_url_rule('/most-favorite', 'most-favorite', create_card_page_route('fetch_most_favorite'))
app.add_url_rule('/latest-completed', 'latest-completed', create_card_page_route('fetch_latest_completed'))
app.add_url_rule('/recent-added', 'recent-added', create_card_page_route('fetch_recently_added'))
app.add_url_rule('/top-upcoming', 'top-upcoming', create_card_page_route('fetch_top_upcoming'))
app.add_url_rule('/movies', 'movies', create_card_page_route('fetch_movie'))
app.add_url_rule('/tv', 'tv', create_card_page_route('fetch_tv'))
app.add_url_rule('/ova', 'ova', create_card_page_route('fetch_ova'))
app.add_url_rule('/ona', 'ona', create_card_page_route('fetch_ona'))
app.add_url_rule('/specials', 'specials', create_card_page_route('fetch_special'))

@app.route("/genre/list")
def genre_list():
    return jsonify(zoro.fetch_genres())

@app.route("/genre/<genre_name>")
def by_genre(genre_name):
    page = request.args.get('page', default=1, type=int)
    data = zoro.genre_search(genre_name, page)
    data['results'] = to_dict_list(data['results'])
    return jsonify(data)

@app.route('/studio/<studio_id>')
def by_studio(studio_id):
    page = request.args.get('page', default=1, type=int)
    data = zoro.fetch_studio(studio_id, page)
    data['results'] = to_dict_list(data['results'])
    return jsonify(data)
    
@app.route('/schedule/<date>')
def schedule(date):
    results = zoro.fetch_schedule(date)
    return jsonify(to_dict_list(results))

@app.route('/spotlight')
def spotlight():
    results = zoro.fetch_spotlight()
    return jsonify(to_dict_list(results))
    
@app.route('/search-suggestions/<query>')
def search_suggestions(query):
    results = zoro.fetch_search_suggestions(query)
    return jsonify(to_dict_list(results))

def get_episode_cover_image(anime_id, episode_number):
    query = """
    query ($id: Int) {
      Media (id: $id, type: ANIME) {
        streamingEpisodes {
          title
          thumbnail
          url
          site
        }
      }
    }
    """
    variables = {'id': anime_id}
    url = 'https://graphql.anilist.co'

    try:
        response = requests.post(url, json={'query': query, 'variables': variables})
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return {'error': f"Error communicating with AniList API: {e}"}
    except json.JSONDecodeError:
        return {'error': "Error decoding the JSON response from the API."}

    try:
        episodes = data['data']['Media']['streamingEpisodes']
    except (KeyError, TypeError):
        return {'error': "Could not find episode data. The anime might not have streaming episodes listed."}

    if not episodes:
        return {'error': "No streaming episodes found for this anime on AniList."}

    if 0 < episode_number <= len(episodes):
        target_episode = episodes[episode_number - 1]
        thumbnail_url = target_episode.get('thumbnail')
        if thumbnail_url:
            return {'episode': episode_number, 'thumbnail': thumbnail_url}
        else:
            return {'error': f"Episode {episode_number} was found, but it does not have a thumbnail image URL."}
    else:
        return {'error': f"Invalid episode number. Please choose between 1 and {len(episodes)}."}

@app.route('/episode_cover', methods=['GET'])
def episode_cover():
    anime_id = request.args.get('anime_id', type=int)
    episode_number = request.args.get('episode_number', type=int)

    if not anime_id or not episode_number:
        return jsonify({'error': 'Please provide both anime_id and episode_number as query parameters.'}), 400

    result = get_episode_cover_image(anime_id, episode_number)
    if 'error' in result:
        return jsonify(result), 400

    return jsonify(result)

def format_timedelta(td):
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds"

@app.route('/next_ep')
def next_episode_info():
    anime_id = request.args.get('id', type=str)
    tz_abbr = request.args.get('timezone', 'BST').upper()
    
    if not anime_id:
        abort(400, description="The anime 'id' is a required query parameter.")

    tz = tznn()

    try:
        iana_tz = tz.get_all_available_time_zones().get(tz_abbr)
        if not iana_tz:
            abort(400, description=f"Unknown timezone abbreviation: {tz_abbr}")
        
        user_tz = pytz.timezone(iana_tz)
    except ValueError:
        abort(400, description=f"Invalid timezone abbreviation: {tz_abbr}")

    utc_now = datetime.now(timezone.utc)

    for i in range(8):
        search_date = utc_now.date() + timedelta(days=i)
        date_str = search_date.strftime('%Y-%m-%d')
        
        try:
            schedule_data = zoro.fetch_schedule(date_str)
        except Exception:
            continue

        for anime in schedule_data:
            if anime.id == anime_id:
                airing_time_str = anime.other_data.get('airingTime')
                if airing_time_str:
                    try:
                        hour, minute = map(int, airing_time_str.split(':'))
                        airing_datetime_utc = datetime(
                            search_date.year, search_date.month, search_date.day,
                            hour, minute, tzinfo=timezone.utc
                        )

                        if airing_datetime_utc > utc_now:
                            time_remaining = airing_datetime_utc - utc_now
                            airing_datetime_local = airing_datetime_utc.astimezone(user_tz)

                            return jsonify({
                                'found': True,
                                'animeId': anime.id,
                                'title': anime.title,
                                'episode': anime.other_data.get('airingEpisode'),
                                'airingAtUTC': airing_datetime_utc.isoformat(),
                                'airingAtLocal': airing_datetime_local.isoformat(),
                                'localTimezone': airing_datetime_local.tzname(),
                                'countdown': format_timedelta(time_remaining)
                            })
                    except ValueError:
                        continue

    return jsonify({
        'found': False,
        'message': 'No upcoming episode found for this anime in the next 7 days.'
    }), 404

def get_anilist_trailer(anime_id: int):
    graphql_url = "https://graphql.anilist.co"
    graphql_query = """
    query ($id: Int) {
      Media(id: $id, type: ANIME) {
        trailer {
          id
          site
          thumbnail
        }
      }
    }
    """
    variables = {"id": anime_id}
    payload = {"query": graphql_query, "variables": variables}

    try:
        response = requests.post(graphql_url, json=payload)
        response.raise_for_status()
        data = response.json()

        media_data = data.get('data', {}).get('Media')
        if not media_data:
            return {"error": f"No media found for AniList ID {anime_id}. It might be an invalid ID."}

        trailer_info = media_data.get('trailer')

        if trailer_info and trailer_info.get('site') == 'youtube' and trailer_info.get('id'):
            return {
                "id": trailer_info['id'],
                "url": f"https://www.youtube.com/watch?v={trailer_info['id']}",
                "embed_url": f"https://www.youtube.com/embed/{trailer_info['id']}",
                "site": "youtube",
                "thumbnail": trailer_info.get('thumbnail')
            }
        else:
            return {"error": "Trailer not found for the given AniList ID."}

    except requests.HTTPError as e:
        return {"error": f"API request failed. Status code: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

@app.route('/trailer')
def trailer():
    anime_id = request.args.get('id', type=int)

    if not anime_id:
        return jsonify({
            'error': "Please provide a valid numeric 'id' as a query parameter."
        }), 400

    result = get_anilist_trailer(anime_id)

    if 'error' in result:
        if "No media found" in result['error'] or "Trailer not found" in result['error']:
            return jsonify(result), 404
        else:
            return jsonify(result), 500
    
    return jsonify(result)
    
if __name__ == '__main__':
    app.run(debug=True, port=5000)
