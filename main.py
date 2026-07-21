import argparse
import base64
import binascii
import csv
import gzip
import html
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from dataclasses import dataclass
from typing import Iterable


LINK_PATTERN = re.compile(r"(?:vless|hysteria2)://[^\s\"'<>]+", re.IGNORECASE)
DATA_PANEL_PATTERN = re.compile(r'data-panel="([^"]+)"', re.IGNORECASE)
ALL_ZERO_UUID = "00000000-0000-0000-0000-000000000000"
HWID_FILE = ".hwid"


class SubscriptionError(Exception):
    pass


class UnsupportedAppError(SubscriptionError):
    pass


@dataclass
class FetchResult:
    text: str
    content_type: str
    profile_name: str


@dataclass
class ProxyLink:
    """A display-friendly representation of a VLESS/Hysteria2 URI."""

    original: str
    protocol: str
    name: str
    server: str
    port: str
    transport: str
    security: str


class ExtractionCancelled(SubscriptionError):
    pass


def parse_proxy_link(link: str) -> ProxyLink:
    """Parse the fields that are useful in the GUI without changing the URI."""
    clean = html.unescape(link.strip())
    parsed = urllib.parse.urlsplit(clean)
    protocol = parsed.scheme.upper()
    if protocol == "HYSTERIA2":
        protocol = "HY2"
    name = urllib.parse.unquote(parsed.fragment).strip() or "Без названия"
    server = parsed.hostname or "?"
    try:
        port = str(parsed.port or "")
    except ValueError:
        port = "?"

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    transport = (params.get("type") or params.get("transport") or [""])[0]
    if not transport and protocol == "HY2":
        transport = "QUIC"
    security = (params.get("security") or [""])[0]
    if not security and protocol == "HY2":
        security = "TLS"
    return ProxyLink(clean, protocol, name, server, port, transport or "—", security or "—")


def load_or_create_hwid() -> str:
    if os.path.exists(HWID_FILE):
        try:
            with open(HWID_FILE, "r", encoding="utf-8") as file:
                value = file.read().strip()
            if value:
                return value
        except OSError:
            pass

    value = str(uuid.uuid4())
    try:
        with open(HWID_FILE, "w", encoding="utf-8", newline="\n") as file:
            file.write(value)
    except OSError:
        pass
    return value


def save_hwid(hwid: str) -> None:
    try:
        with open(HWID_FILE, "w", encoding="utf-8", newline="\n") as file:
            file.write(hwid)
    except OSError:
        pass


def build_request_profiles(hwid: str | None = None) -> list[dict[str, object]]:
    if hwid is None:
        hwid = load_or_create_hwid()
    profiles = [
        {
            "name": "eVPN",
            "headers": {
                "User-Agent": "eVpn/v1.0.0",
                "x-hwid": hwid,
                "x-device-os": "windows",
                "x-ver-os": "10.0.19045",
                "x-device-model": "Desktop",
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate",
            },
        },
        {
            "name": "v2rayN",
            "headers": {
                "User-Agent": "v2rayN/6.42",
                "Accept": "text/plain,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
            },
        },
        {
            "name": "Happ",
            "headers": {
                "User-Agent": "Happ/2.7.0/Windows/2604031533607",
                "x-hwid": hwid,
                "x-device-os": "windows",
                "x-ver-os": "10.0.19045",
                "x-device-model": "Desktop",
                "Accept": "*/*, application/json, text/plain",
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate",
            },
        },
        {
            "name": "iNcy",
            "headers": {
                "User-Agent": "iNcy/1.0.0",
                "x-hwid": hwid,
                "x-device-os": "windows",
                "x-ver-os": "10.0.19045",
                "x-device-model": "Desktop",
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate",
            },
        },

        {
            "name": "Shadowrocket",
            "headers": {
                "User-Agent": "Shadowrocket/3.2.2",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
            },
        },
        {
            "name": "NekoBox",
            "headers": {
                "User-Agent": "NekoBox/3.2.1",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
            },
        },
        {
            "name": "Browser",
            "headers": {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/135.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "ru,en-US;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate",
            },
        },
    ]
    # iNcy is the most reliable profile for the subscriptions this utility targets.
    # Keep the remaining profiles in their declared order after the two preferred ones.
    priority = {"iNcy": 0, "eVPN": 1}
    return sorted(profiles, key=lambda profile: priority.get(str(profile["name"]), 2))


def decode_text(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def format_http_error(error: urllib.error.HTTPError) -> str:
    host = ""
    try:
        host = urllib.parse.urlparse(error.url).netloc
    except Exception:
        host = ""

    if error.code == 502:
        host_part = f" {host}" if host else ""
        return (
            f"The subscription server{host_part} returned 502 Bad Gateway.\n\n"
            "This is a server-side problem in the subscription endpoint or its proxy, "
            "not a bug in this program."
        )

    return f"HTTP error {error.code}: {error.reason}"


def decode_response_body(raw: bytes, content_encoding: str) -> bytes:
    encoding = content_encoding.lower().strip()
    if not encoding:
        return raw
    if encoding == "gzip":
        return gzip.decompress(raw)
    if encoding == "deflate":
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw


def fetch_text(
    url: str,
    headers: dict[str, str],
    timeout: int = 15,
    cancel_event: threading.Event | None = None,
) -> FetchResult:
    parsed = urllib.parse.urlparse(url)
    url_with_cache_buster = url
    if parsed.scheme in ("http", "https"):
        separator = "&" if parsed.query else "?"
        url_with_cache_buster = f"{url}{separator}t={int(uuid.uuid4().int % 10_000_000_000)}"

    request = urllib.request.Request(url_with_cache_buster, headers=headers)
    
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
    except ssl.SSLError:
        pass

    last_error = None
    for attempt in range(3):
        if cancel_event and cancel_event.is_set():
            raise ExtractionCancelled("Операция отменена.")
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:
                raw = response.read()
                content_type = response.headers.get("Content-Type", "")
                content_encoding = response.headers.get("Content-Encoding", "")
                
                raw = decode_response_body(raw, content_encoding)

                return FetchResult(
                    text=decode_text(raw),
                    content_type=content_type,
                    profile_name=headers.get("User-Agent", "unknown"),
                )
        except urllib.error.URLError as e:
            reason_str = str(e.reason).lower()
            if "ssl" in reason_str or "timeout" in reason_str or "timed out" in reason_str:
                last_error = e
                time.sleep(1)
                continue
            raise

    if last_error:
        raise last_error
    raise urllib.error.URLError("Unknown fetch error")


def extract_proxy_links(text: str) -> list[str]:
    text = html.unescape(text)
    seen: set[str] = set()
    links: list[str] = []

    for match in LINK_PATTERN.findall(text):
        clean = match.strip().rstrip("),.;")
        if clean not in seen:
            seen.add(clean)
            links.append(clean)

    return links


def decode_base64_variants(text: str) -> Iterable[str]:
    compact = "".join(text.split())
    if not compact:
        return []

    candidates = [compact]
    padded = compact + "=" * (-len(compact) % 4)
    if padded != compact:
        candidates.append(padded)

    decoded_results: list[str] = []
    for candidate in candidates:
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(candidate)
            except (binascii.Error, ValueError):
                continue

            decoded_results.append(decode_text(decoded))

    return decoded_results


def is_placeholder_link(link: str) -> bool:
    decoded = urllib.parse.unquote(link)
    return (
        ALL_ZERO_UUID in decoded
        or "@0.0.0.0:1" in decoded
        or "App not supported" in decoded
    )


def looks_like_html(text: str) -> bool:
    trimmed = text.lstrip().lower()
    return trimmed.startswith("<!doctype html") or trimmed.startswith("<html")


def extract_panel_payload(text: str) -> dict | None:
    match = DATA_PANEL_PATTERN.search(text)
    if not match:
        return None

    try:
        raw = base64.b64decode(match.group(1))
        return json.loads(decode_text(raw))
    except (binascii.Error, json.JSONDecodeError, ValueError):
        return None


def build_panel_message(panel_payload: dict, unsupported_placeholder_seen: bool) -> str:
    response = panel_payload.get("response", {})
    user = response.get("user", {})
    username = user.get("username", "unknown")
    status = user.get("userStatus", "unknown")
    expires_at = user.get("expiresAt", "unknown")
    links = response.get("links", [])

    message = (
        "The subscription page is valid, but it does not expose raw VLESS/Hysteria2 links.\n\n"
        f"User: {username}\n"
        f"Status: {status}\n"
        f"Expires: {expires_at}\n"
        f"Embedded links in page payload: {len(links)}"
    )

    if unsupported_placeholder_seen:
        message += (
            "\n\nA direct request to this Remnawave subscription returns the placeholder "
            "'App not supported'. That means the provider gives real nodes only to supported "
            "apps like eVPN/Happ, not as public raw VLESS/Hysteria2 links."
        )

    return message


def extract_links_from_text(text: str) -> list[str]:
    direct_links = extract_proxy_links(text)
    if direct_links:
        return direct_links

    for decoded_text in decode_base64_variants(text):
        decoded_links = extract_proxy_links(decoded_text)
        if decoded_links:
            return decoded_links

    return []


def extract_links_from_json(text: str) -> list[str]:
    """Find links in JSON responses used by some app-specific subscription profiles."""
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        for link in extract_proxy_links(value):
            if link not in seen and not is_placeholder_link(link):
                seen.add(link)
                found.append(link)

    def walk(value: object) -> None:
        if isinstance(value, str):
            add(value)
            return
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    return found


def get_vless_links_from_subscription(
    url: str,
    use_proxy: bool = False,
    hwid: str | None = None,
    profile_name: str | None = None,
    cancel_event: threading.Event | None = None,
) -> list[str]:
    panel_payload: dict | None = None
    unsupported_placeholder_seen = False
    last_http_error: urllib.error.HTTPError | None = None
    last_url_error: urllib.error.URLError | None = None
    last_profile_name = "unknown"
    last_content_type = ""

    profiles = build_request_profiles(hwid)
    if profile_name and profile_name != "Auto (Try all)":
        profiles = [p for p in profiles if p["name"] == profile_name]

    for profile in profiles:
        if cancel_event and cancel_event.is_set():
            raise ExtractionCancelled("Операция отменена.")
        try:
            result = fetch_text(
                url,
                headers=profile["headers"],
                timeout=25 if use_proxy else 15,
                cancel_event=cancel_event,
            )
            last_profile_name = str(profile["name"])
            last_content_type = result.content_type
        except urllib.error.HTTPError as error:
            last_http_error = error
            continue
        except urllib.error.URLError as error:
            last_url_error = error
            reason_str = str(error.reason).lower()
            if "timeout" in reason_str or "ssl" in reason_str:
                break
            continue

        links = extract_links_from_text(result.text)
        if not links and ("json" in result.content_type.lower() or result.text.lstrip().startswith(("{", "["))):
            links = extract_links_from_json(result.text)
        if links:
            real_links = [link for link in links if not is_placeholder_link(link)]
            if not real_links:
                unsupported_placeholder_seen = True
            else:
                return real_links

        if looks_like_html(result.text):
            parsed_panel = extract_panel_payload(result.text)
            if parsed_panel:
                panel_payload = parsed_panel
                page_links = list(dict.fromkeys(
                    html.unescape(value)
                    for value in parsed_panel.get("response", {}).get("links", [])
                    if isinstance(value, str)
                    and (value.lower().startswith("vless://") or value.lower().startswith("hysteria2://"))
                    and not is_placeholder_link(value)
                ))
                if page_links:
                    return page_links

        if "App not supported" in urllib.parse.unquote(result.text):
            unsupported_placeholder_seen = True

    if panel_payload:
        raise SubscriptionError(build_panel_message(panel_payload, unsupported_placeholder_seen))

    if unsupported_placeholder_seen:
        raise UnsupportedAppError(
            "The subscription endpoint returns only the placeholder 'App not supported'.\n\n"
            "This Remnawave setup does not expose real raw VLESS/Hysteria2 links to unsupported clients. "
            "Import works only through the provider's supported apps."
        )

    if last_url_error and not use_proxy:
        for proxy_base in ("https://api.allorigins.win/raw?url=", "https://corsproxy.io/?"):
            proxy_url = f"{proxy_base}{urllib.parse.quote(url, safe='')}"
            try:
                return get_vless_links_from_subscription(
                    proxy_url,
                    use_proxy=True,
                    hwid=hwid,
                    profile_name=profile_name,
                    cancel_event=cancel_event,
                )
            except ExtractionCancelled:
                raise
            except Exception:
                continue

    if last_http_error:
        raise last_http_error

    if last_url_error:
        raise last_url_error

    content_type = last_content_type or "не указан"
    raise SubscriptionError(
        "Could not find any real proxy links (vless/hysteria2) in the server response.\n\n"
        f"Profile: {last_profile_name}\n"
        f"Content-Type: {content_type}\n"
        "The provider may return an app-specific or encrypted format for this profile."
    )


def save_links(links: list[str], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8", newline="\n") as file:
        file.write("\n".join(links))
        file.write("\n")


def run_cli(url: str, output_path: str | None) -> int:
    try:
        links = get_vless_links_from_subscription(url)
    except urllib.error.HTTPError as error:
        print(format_http_error(error), file=sys.stderr)
        return 1
    except urllib.error.URLError as error:
        print(f"Network error: {error.reason}", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if output_path:
        save_links(links, output_path)
        print(f"Saved {len(links)} link(s) to {output_path}")
    else:
        print("\n".join(links))

    return 0


def run_gui() -> int:
    import tkinter as tk
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title("VLESS Extractor")
    root.geometry("1120x740")
    root.minsize(900, 600)

    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    all_links: dict[str, ProxyLink] = {}
    row_links: dict[str, ProxyLink] = {}
    availability: dict[str, str] = {}
    cancel_event = threading.Event()
    working = False
    dark_mode = tk.BooleanVar(value=False)
    hwid_var = tk.StringVar(value=load_or_create_hwid())
    profile_var = tk.StringVar(value="Auto (Try all)")
    search_var = tk.StringVar()
    protocol_var = tk.StringVar(value="Все")
    security_var = tk.StringVar(value="Все")
    replace_var = tk.BooleanVar(value=True)
    status_var = tk.StringVar(value="Готово")
    count_var = tk.StringVar(value="Серверов: 0")
    sort_column = "name"
    sort_reverse = False

    colors = {
        "light": {
            "bg": "#F3F4F6", "panel": "#FFFFFF", "fg": "#1F2937",
            "muted": "#6B7280", "entry": "#FFFFFF", "border": "#D1D5DB",
            "accent": "#2563EB", "select": "#DBEAFE",
        },
        "dark": {
            "bg": "#111827", "panel": "#1F2937", "fg": "#F9FAFB",
            "muted": "#9CA3AF", "entry": "#111827", "border": "#374151",
            "accent": "#3B82F6", "select": "#1D4ED8",
        },
    }

    def generate_hwid() -> None:
        new_hwid = str(uuid.uuid4())
        hwid_var.set(new_hwid)
        save_hwid(new_hwid)
        status_var.set("Создан новый HWID")

    def set_busy(value: bool, text: str = "") -> None:
        nonlocal working
        working = value
        extract_button.configure(state="disabled" if value else "normal")
        check_button.configure(state="disabled" if value else "normal")
        cancel_button.configure(state="normal" if value else "disabled")
        if value:
            progress.start(10)
        else:
            progress.stop()
        if text:
            status_var.set(text)

    def filtered_links() -> list[ProxyLink]:
        query = search_var.get().strip().casefold()
        protocol = protocol_var.get()
        security = security_var.get()
        result: list[ProxyLink] = []
        for item in all_links.values():
            haystack = " ".join((item.name, item.server, item.protocol, item.transport, item.security)).casefold()
            if query and query not in haystack:
                continue
            if protocol != "Все" and item.protocol != protocol:
                continue
            if security != "Все":
                if security == "Без защиты" and item.security != "—":
                    continue
                if security != "Без защиты" and security.casefold() not in item.security.casefold():
                    continue
            result.append(item)

        def sort_key(item: ProxyLink):
            values = {
                "protocol": item.protocol,
                "name": item.name,
                "server": item.server,
                "port": int(item.port) if item.port.isdigit() else 0,
                "transport": item.transport,
                "security": item.security,
                "availability": availability.get(item.original, "—"),
            }
            value = values.get(sort_column, item.name)
            return value.casefold() if isinstance(value, str) else value

        return sorted(result, key=sort_key, reverse=sort_reverse)

    def refresh_table() -> None:
        previous = {row_links[iid].original for iid in tree.selection() if iid in row_links}
        tree.delete(*tree.get_children())
        row_links.clear()
        visible = filtered_links()
        for index, item in enumerate(visible):
            iid = f"row_{index}"
            row_links[iid] = item
            tree.insert(
                "", "end", iid=iid,
                values=(
                    item.protocol, item.name, item.server, item.port,
                    item.transport, item.security, availability.get(item.original, "—"),
                ),
            )
            if item.original in previous:
                tree.selection_add(iid)
        count_var.set(f"Показано: {len(visible)} из {len(all_links)}")

    def change_sort(column: str) -> None:
        nonlocal sort_column, sort_reverse
        if sort_column == column:
            sort_reverse = not sort_reverse
        else:
            sort_column = column
            sort_reverse = False
        refresh_table()

    def selected_or_visible() -> list[ProxyLink]:
        selected = [row_links[iid] for iid in tree.selection() if iid in row_links]
        return selected or [row_links[iid] for iid in tree.get_children() if iid in row_links]

    def copy_links() -> None:
        items = selected_or_visible()
        if not items:
            messagebox.showinfo("Нет данных", "Сначала получите ссылки.", parent=root)
            return
        root.clipboard_clear()
        root.clipboard_append("\n".join(item.original for item in items))
        status_var.set(f"Скопировано ссылок: {len(items)}")

    def copy_server() -> None:
        items = selected_or_visible()
        if not items:
            return
        value = items[0].server + (f":{items[0].port}" if items[0].port else "")
        root.clipboard_clear()
        root.clipboard_append(value)
        status_var.set(f"Скопировано: {value}")

    def show_details(event=None) -> None:
        if event is not None:
            row = tree.identify_row(event.y)
            if row:
                tree.selection_set(row)
        items = selected_or_visible()
        if not items:
            return
        item = items[0]
        parsed = urllib.parse.urlsplit(item.original)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        lines = [
            f"Протокол: {item.protocol}", f"Название: {item.name}",
            f"Сервер: {item.server}", f"Порт: {item.port or '—'}",
            f"Транспорт: {item.transport}", f"Защита: {item.security}", "",
            "Параметры:",
        ]
        lines.extend(f"  {key} = {value}" for key, value in params)
        lines.extend(("", "Исходная ссылка:", item.original))

        window = tk.Toplevel(root)
        window.title("Параметры сервера")
        window.geometry("760x460")
        window.transient(root)
        text_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Consolas", 10), padx=10, pady=10)
        text_box.pack(fill="both", expand=True, padx=12, pady=12)
        text_box.insert("1.0", "\n".join(lines))
        text_box.configure(state="disabled")

    def save_export(kind: str) -> None:
        items = selected_or_visible()
        if not items:
            messagebox.showinfo("Нет данных", "Нет ссылок для экспорта.", parent=root)
            return
        settings = {
            "txt": ("Текстовый файл", ".txt", [("TXT", "*.txt")]),
            "base64": ("Base64-подписка", ".txt", [("TXT", "*.txt")]),
            "json": ("JSON", ".json", [("JSON", "*.json")]),
            "csv": ("CSV", ".csv", [("CSV", "*.csv")]),
        }
        title, extension, filetypes = settings[kind]
        path = filedialog.asksaveasfilename(title=f"Сохранить: {title}", defaultextension=extension, filetypes=filetypes)
        if not path:
            return
        try:
            if kind == "txt":
                with open(path, "w", encoding="utf-8", newline="\n") as file:
                    file.write("\n".join(item.original for item in items) + "\n")
            elif kind == "base64":
                raw = "\n".join(item.original for item in items).encode("utf-8")
                with open(path, "w", encoding="ascii", newline="\n") as file:
                    file.write(base64.b64encode(raw).decode("ascii") + "\n")
            elif kind == "json":
                payload = [
                    {
                        "protocol": item.protocol, "name": item.name, "server": item.server,
                        "port": item.port, "transport": item.transport,
                        "security": item.security, "link": item.original,
                    }
                    for item in items
                ]
                with open(path, "w", encoding="utf-8", newline="\n") as file:
                    json.dump(payload, file, ensure_ascii=False, indent=2)
                    file.write("\n")
            else:
                with open(path, "w", encoding="utf-8-sig", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow(("protocol", "name", "server", "port", "transport", "security", "link"))
                    for item in items:
                        writer.writerow((item.protocol, item.name, item.server, item.port, item.transport, item.security, item.original))
        except OSError as error:
            messagebox.showerror("Ошибка сохранения", str(error), parent=root)
            return
        status_var.set(f"Сохранено ссылок: {len(items)} → {path}")

    def paste_sources() -> None:
        try:
            content = root.clipboard_get()
        except tk.TclError:
            return
        source_box.delete("1.0", tk.END)
        source_box.insert("1.0", content)

    def extract_batch() -> None:
        if working:
            return
        urls = [line.strip() for line in source_box.get("1.0", tk.END).splitlines() if line.strip()]
        if not urls:
            messagebox.showwarning("Нет URL", "Вставьте одну или несколько ссылок подписки.", parent=root)
            return
        if replace_var.get():
            all_links.clear()
            availability.clear()
            refresh_table()

        cancel_event.clear()
        set_busy(True, f"Подготовка подписок: {len(urls)}")
        current_hwid = hwid_var.get().strip()
        current_profile = profile_var.get()

        def worker() -> None:
            collected: list[str] = []
            errors: list[str] = []
            for index, url in enumerate(urls, start=1):
                if cancel_event.is_set():
                    break
                root.after(0, lambda i=index, total=len(urls): status_var.set(f"Загрузка подписки {i} из {total}…"))
                try:
                    collected.extend(get_vless_links_from_subscription(
                        url, hwid=current_hwid, profile_name=current_profile, cancel_event=cancel_event
                    ))
                except ExtractionCancelled:
                    break
                except urllib.error.HTTPError as error:
                    errors.append(f"{index}: {format_http_error(error).splitlines()[0]}")
                except urllib.error.URLError as error:
                    errors.append(f"{index}: {error.reason}")
                except Exception as error:
                    errors.append(f"{index}: {error}")
            root.after(0, finish, collected, errors, cancel_event.is_set())

        def finish(links: list[str], errors: list[str], cancelled: bool) -> None:
            for link in links:
                try:
                    item = parse_proxy_link(link)
                except (TypeError, ValueError):
                    continue
                all_links.setdefault(item.original, item)
            refresh_table()
            set_busy(False)
            if cancelled:
                status_var.set(f"Остановлено. Получено серверов: {len(all_links)}")
            elif errors:
                status_var.set(f"Готово с ошибками. Серверов: {len(all_links)}")
                preview = "\n".join(errors[:8])
                if len(errors) > 8:
                    preview += f"\n…и ещё {len(errors) - 8}"
                messagebox.showwarning("Некоторые подписки не загружены", preview, parent=root)
            else:
                status_var.set(f"Готово. Уникальных серверов: {len(all_links)}")

        threading.Thread(target=worker, daemon=True).start()

    def cancel_work() -> None:
        cancel_event.set()
        status_var.set("Отмена… текущий сетевой запрос может завершаться несколько секунд")
        cancel_button.configure(state="disabled")

    def check_availability() -> None:
        if working:
            return
        items = selected_or_visible()
        targets = [item for item in items if item.server not in ("", "?") and item.port.isdigit()]
        if not targets:
            messagebox.showinfo("Нет серверов", "Нет подходящих серверов для проверки.", parent=root)
            return
        cancel_event.clear()
        set_busy(True, f"Проверка серверов: {len(targets)}")

        def probe(item: ProxyLink) -> tuple[str, str]:
            if cancel_event.is_set():
                return item.original, "Отменено"
            port = int(item.port)
            started = time.perf_counter()
            try:
                if item.protocol == "HY2":
                    socket.getaddrinfo(item.server, port, type=socket.SOCK_DGRAM)
                    return item.original, "DNS ✓"
                with socket.create_connection((item.server, port), timeout=3):
                    elapsed = int((time.perf_counter() - started) * 1000)
                    return item.original, f"{elapsed} ms"
            except (OSError, ValueError):
                return item.original, "Недоступен"

        def worker() -> None:
            results: list[tuple[str, str]] = []
            with ThreadPoolExecutor(max_workers=min(10, len(targets))) as executor:
                futures = [executor.submit(probe, item) for item in targets]
                for future in as_completed(futures):
                    results.append(future.result())
            root.after(0, finish, results)

        def finish(results: list[tuple[str, str]]) -> None:
            for original, result in results:
                availability[original] = result
            refresh_table()
            set_busy(False, f"Проверено серверов: {len(results)}")

        threading.Thread(target=worker, daemon=True).start()

    def apply_theme() -> None:
        palette = colors["dark" if dark_mode.get() else "light"]
        root.configure(bg=palette["bg"])
        style.configure("TFrame", background=palette["bg"])
        style.configure("Panel.TFrame", background=palette["panel"])
        style.configure("TLabel", background=palette["bg"], foreground=palette["fg"], font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=palette["panel"], foreground=palette["fg"], font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=palette["bg"], foreground=palette["fg"], font=("Segoe UI", 18, "bold"))
        style.configure("Muted.TLabel", background=palette["bg"], foreground=palette["muted"], font=("Segoe UI", 9))
        style.configure("TButton", padding=(10, 6), font=("Segoe UI", 10))
        style.configure("Accent.TButton", background=palette["accent"], foreground="#FFFFFF", padding=(12, 7))
        style.map("Accent.TButton", background=[("active", palette["accent"]), ("disabled", palette["border"])])
        style.configure("TEntry", fieldbackground=palette["entry"], foreground=palette["fg"])
        style.configure("TCombobox", fieldbackground=palette["entry"], foreground=palette["fg"])
        style.configure(
            "Treeview", background=palette["panel"], fieldbackground=palette["panel"],
            foreground=palette["fg"], rowheight=29, bordercolor=palette["border"],
        )
        style.map("Treeview", background=[("selected", palette["select"])], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=palette["bg"], foreground=palette["fg"], padding=(6, 7))
        style.configure("TCheckbutton", background=palette["bg"], foreground=palette["fg"])
        style.configure("TLabelframe", background=palette["bg"], bordercolor=palette["border"])
        style.configure("TLabelframe.Label", background=palette["bg"], foreground=palette["fg"])
        source_box.configure(bg=palette["entry"], fg=palette["fg"], insertbackground=palette["fg"])
        theme_button.configure(text="☀ Светлая" if dark_mode.get() else "☾ Тёмная")

    def toggle_theme() -> None:
        dark_mode.set(not dark_mode.get())
        apply_theme()

    def on_right_click(event) -> None:
        row = tree.identify_row(event.y)
        if row and row not in tree.selection():
            tree.selection_set(row)
        context_menu.tk_popup(event.x_root, event.y_root)

    def on_close() -> None:
        cancel_event.set()
        root.destroy()

    outer = ttk.Frame(root, padding=16)
    outer.grid(row=0, column=0, sticky="nsew")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(4, weight=1)

    header = ttk.Frame(outer)
    header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
    header.columnconfigure(0, weight=1)
    ttk.Label(header, text="VLESS Extractor", style="Title.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(header, text="Менеджер подписок VLESS и Hysteria2", style="Muted.TLabel").grid(row=1, column=0, sticky="w")
    theme_button = ttk.Button(header, text="☾ Тёмная", command=toggle_theme)
    theme_button.grid(row=0, column=1, rowspan=2, sticky="e")

    source_frame = ttk.LabelFrame(outer, text=" Ссылки подписок — по одной на строку ", padding=10)
    source_frame.grid(row=1, column=0, sticky="ew")
    source_frame.columnconfigure(0, weight=1)
    source_box = scrolledtext.ScrolledText(source_frame, height=3, wrap=tk.CHAR, font=("Consolas", 10), padx=8, pady=6)
    source_box.grid(row=0, column=0, rowspan=2, sticky="ew")
    ttk.Button(source_frame, text="Вставить", command=paste_sources, width=13).grid(row=0, column=1, padx=(10, 0), sticky="n")
    extract_button = ttk.Button(source_frame, text="Получить", command=extract_batch, style="Accent.TButton", width=13)
    extract_button.grid(row=1, column=1, padx=(10, 0), pady=(5, 0), sticky="s")

    options = ttk.Frame(outer)
    options.grid(row=2, column=0, sticky="ew", pady=10)
    options.columnconfigure(3, weight=1)
    ttk.Label(options, text="Профиль:").grid(row=0, column=0, sticky="w")
    profile_values = ["Auto (Try all)"] + [str(profile["name"]) for profile in build_request_profiles(hwid_var.get())]
    ttk.Combobox(options, textvariable=profile_var, values=profile_values, state="readonly", width=17).grid(row=0, column=1, padx=(6, 16))
    ttk.Label(options, text="HWID:").grid(row=0, column=2, sticky="w")
    ttk.Entry(options, textvariable=hwid_var, font=("Consolas", 9)).grid(row=0, column=3, padx=6, sticky="ew")
    ttk.Button(options, text="Новый HWID", command=generate_hwid).grid(row=0, column=4, padx=(0, 16))
    ttk.Checkbutton(options, text="Заменить текущий список", variable=replace_var).grid(row=0, column=5)

    filters = ttk.Frame(outer)
    filters.grid(row=3, column=0, sticky="ew", pady=(0, 8))
    filters.columnconfigure(1, weight=1)
    ttk.Label(filters, text="Поиск:").grid(row=0, column=0, sticky="w")
    search_entry = ttk.Entry(filters, textvariable=search_var)
    search_entry.grid(row=0, column=1, padx=(6, 14), sticky="ew")
    ttk.Label(filters, text="Протокол:").grid(row=0, column=2)
    protocol_box = ttk.Combobox(filters, textvariable=protocol_var, values=("Все", "VLESS", "HY2"), state="readonly", width=10)
    protocol_box.grid(row=0, column=3, padx=(6, 14))
    ttk.Label(filters, text="Защита:").grid(row=0, column=4)
    security_box = ttk.Combobox(filters, textvariable=security_var, values=("Все", "Reality", "TLS", "Без защиты"), state="readonly", width=13)
    security_box.grid(row=0, column=5, padx=(6, 0))

    table_frame = ttk.Frame(outer)
    table_frame.grid(row=4, column=0, sticky="nsew")
    table_frame.columnconfigure(0, weight=1)
    table_frame.rowconfigure(0, weight=1)
    columns = ("protocol", "name", "server", "port", "transport", "security", "availability")
    tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
    headings = {
        "protocol": "Тип", "name": "Название", "server": "Сервер", "port": "Порт",
        "transport": "Транспорт", "security": "Защита", "availability": "Доступность",
    }
    widths = {"protocol": 70, "name": 235, "server": 230, "port": 70, "transport": 100, "security": 100, "availability": 110}
    for column in columns:
        tree.heading(column, text=headings[column], command=lambda value=column: change_sort(value))
        tree.column(column, width=widths[column], minwidth=55, anchor="w", stretch=column in ("name", "server"))
    tree.grid(row=0, column=0, sticky="nsew")
    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    tree.configure(yscrollcommand=scrollbar.set)
    tree.bind("<Double-1>", show_details)
    tree.bind("<Button-3>", on_right_click)

    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="Копировать ссылку", command=copy_links)
    context_menu.add_command(label="Копировать сервер:порт", command=copy_server)
    context_menu.add_separator()
    context_menu.add_command(label="Показать параметры", command=show_details)

    actions = ttk.Frame(outer)
    actions.grid(row=5, column=0, sticky="ew", pady=(10, 6))
    actions.columnconfigure(6, weight=1)
    check_button = ttk.Button(actions, text="Проверить", command=check_availability)
    check_button.grid(row=0, column=0)
    ttk.Button(actions, text="Копировать", command=copy_links).grid(row=0, column=1, padx=(8, 0))
    export_button = ttk.Menubutton(actions, text="Сохранить ▾")
    export_menu = tk.Menu(export_button, tearoff=0)
    export_menu.add_command(label="Ссылки TXT", command=lambda: save_export("txt"))
    export_menu.add_command(label="Base64-подписка", command=lambda: save_export("base64"))
    export_menu.add_command(label="JSON с параметрами", command=lambda: save_export("json"))
    export_menu.add_command(label="CSV-таблица", command=lambda: save_export("csv"))
    export_button.configure(menu=export_menu)
    export_button.grid(row=0, column=2, padx=(8, 0))
    cancel_button = ttk.Button(actions, text="Отмена", command=cancel_work, state="disabled")
    cancel_button.grid(row=0, column=3, padx=(8, 0))
    ttk.Label(actions, textvariable=count_var, style="Muted.TLabel").grid(row=0, column=7, sticky="e")

    footer = ttk.Frame(outer)
    footer.grid(row=6, column=0, sticky="ew")
    footer.columnconfigure(0, weight=1)
    ttk.Label(footer, textvariable=status_var, style="Muted.TLabel").grid(row=0, column=0, sticky="w")
    progress = ttk.Progressbar(footer, mode="indeterminate", length=160)
    progress.grid(row=0, column=1, sticky="e")

    search_var.trace_add("write", lambda *_: refresh_table())
    protocol_box.bind("<<ComboboxSelected>>", lambda *_: refresh_table())
    security_box.bind("<<ComboboxSelected>>", lambda *_: refresh_table())
    root.bind("<Control-f>", lambda _event: (search_entry.focus_set(), "break")[1])
    root.bind("<Control-s>", lambda _event: save_export("txt"))
    root.bind("<F5>", lambda _event: extract_batch())
    root.protocol("WM_DELETE_WINDOW", on_close)
    apply_theme()

    root.mainloop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract raw VLESS/Hysteria2 links from a subscription URL.")
    parser.add_argument("url", nargs="?", help="Subscription URL.")
    parser.add_argument("-o", "--output", help="Path to save the resulting TXT file.")
    parser.add_argument("--no-gui", action="store_true", help="Run in console mode only.")
    args = parser.parse_args()

    if args.url:
        return run_cli(args.url, args.output)

    if args.no_gui:
        parser.error("In --no-gui mode you must provide a URL.")

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
