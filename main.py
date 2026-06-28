import argparse
import base64
import binascii
import gzip
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from dataclasses import dataclass
from typing import Iterable


VLESS_PATTERN = re.compile(r"vless://[^\s\"'<>]+", re.IGNORECASE)
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
    return [
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
                "Accept": "application/json, text/plain, */*",
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


def fetch_text(url: str, headers: dict[str, str], timeout: int = 15) -> FetchResult:
    parsed = urllib.parse.urlparse(url)
    url_with_cache_buster = url
    if parsed.scheme in ("http", "https"):
        separator = "&" if parsed.query else "?"
        url_with_cache_buster = f"{url}{separator}t={int(uuid.uuid4().int % 10_000_000_000)}"

    request = urllib.request.Request(url_with_cache_buster, headers=headers)
    
    import ssl
    import time
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
    except ssl.SSLError:
        pass

    last_error = None
    for attempt in range(3):
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


def extract_vless_links(text: str) -> list[str]:
    seen: set[str] = set()
    links: list[str] = []

    for match in VLESS_PATTERN.findall(text):
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
        "The subscription page is valid, but it does not expose raw VLESS links.\n\n"
        f"User: {username}\n"
        f"Status: {status}\n"
        f"Expires: {expires_at}\n"
        f"Embedded links in page payload: {len(links)}"
    )

    if unsupported_placeholder_seen:
        message += (
            "\n\nA direct request to this Remnawave subscription returns the placeholder "
            "'App not supported'. That means the provider gives real nodes only to supported "
            "apps like eVPN/Happ, not as public raw VLESS links."
        )

    return message


def extract_links_from_text(text: str) -> list[str]:
    direct_links = extract_vless_links(text)
    if direct_links:
        return direct_links

    for decoded_text in decode_base64_variants(text):
        decoded_links = extract_vless_links(decoded_text)
        if decoded_links:
            return decoded_links

    return []


def get_vless_links_from_subscription(
    url: str, use_proxy: bool = False, hwid: str | None = None, profile_name: str | None = None
) -> list[str]:
    panel_payload: dict | None = None
    unsupported_placeholder_seen = False
    last_http_error: urllib.error.HTTPError | None = None
    last_url_error: urllib.error.URLError | None = None

    profiles = build_request_profiles(hwid)
    if profile_name and profile_name != "Auto (Try all)":
        profiles = [p for p in profiles if p["name"] == profile_name]

    for profile in profiles:
        try:
            result = fetch_text(url, headers=profile["headers"], timeout=25 if use_proxy else 15)
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
        if links:
            if all(is_placeholder_link(link) for link in links):
                unsupported_placeholder_seen = True
            else:
                return links

        if looks_like_html(result.text):
            parsed_panel = extract_panel_payload(result.text)
            if parsed_panel:
                panel_payload = parsed_panel
                page_links = [
                    value
                    for value in parsed_panel.get("response", {}).get("links", [])
                    if isinstance(value, str) and value.lower().startswith("vless://")
                ]
                if page_links:
                    return page_links

        if "App not supported" in urllib.parse.unquote(result.text):
            unsupported_placeholder_seen = True

    if panel_payload:
        raise SubscriptionError(build_panel_message(panel_payload, unsupported_placeholder_seen))

    if unsupported_placeholder_seen:
        raise UnsupportedAppError(
            "The subscription endpoint returns only the placeholder 'App not supported'.\n\n"
            "This Remnawave setup does not expose real raw VLESS links to unsupported clients. "
            "Import works only through the provider's supported apps."
        )

    if last_url_error and not use_proxy:
        for proxy_base in ("https://api.allorigins.win/raw?url=", "https://corsproxy.io/?"):
            proxy_url = f"{proxy_base}{urllib.parse.quote(url, safe='')}"
            try:
                return get_vless_links_from_subscription(
                    proxy_url, use_proxy=True, hwid=hwid, profile_name=profile_name
                )
            except Exception:
                continue

    if last_http_error:
        raise last_http_error

    if last_url_error:
        raise last_url_error

    raise SubscriptionError("Could not find any real vless:// links in the server response.")


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
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import threading

    root = tk.Tk()
    root.title("VLESS Extractor")
    root.geometry("900x620")
    root.configure(bg="#F3F4F6")

    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")

    style.configure("TFrame", background="#F3F4F6")
    style.configure("TLabel", background="#F3F4F6", font=("Segoe UI", 10))
    style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground="#1F2937")
    style.configure("TButton", font=("Segoe UI", 10), padding=6)

    url_var = tk.StringVar()
    placeholder_text = "Вставьте вашу подписку (https://...)"

    hwid_var = tk.StringVar(value=load_or_create_hwid())

    def generate_hwid():
        new_hwid = str(uuid.uuid4())
        hwid_var.set(new_hwid)
        save_hwid(new_hwid)

    def extract() -> None:
        url = url_var.get().strip()
        if not url or url == placeholder_text:
            messagebox.showwarning("Missing URL", "Enter a subscription URL.")
            return

        output_box.delete("1.0", tk.END)
        status_var.set("Extracting...")
        extract_button.config(state="disabled")

        current_hwid = hwid_var.get().strip()
        current_profile = "Auto (Try all)"

        def worker() -> None:
            try:
                links = get_vless_links_from_subscription(
                    url, hwid=current_hwid, profile_name=current_profile
                )
                root.after(0, on_success, links)
            except urllib.error.HTTPError as error:
                msg = format_http_error(error)
                root.after(0, on_error, "HTTP Error", msg)
            except urllib.error.URLError as error:
                msg = str(error.reason)
                root.after(0, on_error, "Network Error", msg)
            except Exception as error:
                msg = str(error)
                root.after(0, on_error, "Error", msg)

        def on_success(links: list[str]) -> None:
            output_box.insert("1.0", "\n".join(links))
            status_var.set(f"Found links: {len(links)}")
            extract_button.config(state="normal")

        def on_error(title: str, msg: str) -> None:
            status_var.set("Error during extraction")
            extract_button.config(state="normal")
            messagebox.showerror(title, msg, parent=root)

        threading.Thread(target=worker, daemon=True).start()

    def save() -> None:
        content = output_box.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("No Data", "Extract links first.")
            return

        path = filedialog.asksaveasfilename(
            title="Save links",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8", newline="\n") as file:
            file.write(content)
            file.write("\n")

        status_var.set(f"Saved to: {path}")

    def copy_all() -> None:
        content = output_box.get("1.0", tk.END).strip()
        if content:
            root.clipboard_clear()
            root.clipboard_append(content)
            status_var.set("Copied all links to clipboard!")

    root.columnconfigure(0, weight=1)
    root.rowconfigure(4, weight=1)

    title = ttk.Label(
        root,
        text="Extract raw VLESS links from a subscription URL",
        style="Title.TLabel"
    )
    title.grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))

    url_entry = ttk.Entry(root, textvariable=url_var, font=("Consolas", 11))
    url_entry.grid(row=1, column=0, sticky="ew", padx=16)
    url_entry.insert(0, placeholder_text)

    def on_focus_in(event):
        if url_entry.get() == placeholder_text:
            url_entry.delete(0, tk.END)

    def on_focus_out(event):
        if not url_entry.get():
            url_entry.insert(0, placeholder_text)

    url_entry.bind("<FocusIn>", on_focus_in)
    url_entry.bind("<FocusOut>", on_focus_out)

    def paste_clipboard():
        try:
            content = root.clipboard_get()
            try:
                url_entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                pass
            if url_entry.get() == placeholder_text:
                url_entry.delete(0, tk.END)
            url_entry.insert(tk.INSERT, content)
        except tk.TclError:
            pass

    def handle_keypress(event: tk.Event) -> str | None:
        if event.state & 4 and (event.keysym.lower() == 'v' or getattr(event, 'keycode', 0) == 86):
            paste_clipboard()
            return "break"
        return None

    url_entry.bind("<KeyPress>", handle_keypress)

    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Paste", command=paste_clipboard)
    url_entry.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))

    settings_frame = ttk.Frame(root)
    settings_frame.grid(row=2, column=0, sticky="ew", padx=16, pady=(12, 0))
    settings_frame.columnconfigure(1, weight=1)
    
    ttk.Label(settings_frame, text="HWID:").grid(row=0, column=0, sticky="w", pady=4)
    hwid_entry = ttk.Entry(settings_frame, textvariable=hwid_var, font=("Consolas", 10))
    hwid_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=4)
    
    gen_btn = ttk.Button(settings_frame, text="Generate HWID", command=generate_hwid)
    gen_btn.grid(row=0, column=2, sticky="e", pady=4)

    button_frame = ttk.Frame(root)
    button_frame.grid(row=3, column=0, sticky="w", padx=16, pady=12)

    extract_button = ttk.Button(button_frame, text="Extract", width=15, command=extract)
    extract_button.pack(side=tk.LEFT)

    copy_button = ttk.Button(button_frame, text="Copy", width=15, command=copy_all)
    copy_button.pack(side=tk.LEFT, padx=(10, 0))

    save_button = ttk.Button(button_frame, text="Save to TXT", width=15, command=save)
    save_button.pack(side=tk.LEFT, padx=(10, 0))

    output_box = scrolledtext.ScrolledText(
        root, wrap=tk.WORD, font=("Consolas", 10),
        bd=0, padx=10, pady=10, bg="#ffffff"
    )
    output_box.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 10))

    def copy_selection(event=None):
        try:
            content = output_box.get(tk.SEL_FIRST, tk.SEL_LAST)
            root.clipboard_clear()
            root.clipboard_append(content)
        except tk.TclError:
            pass # No selection
        return "break"

    def handle_output_keypress(event: tk.Event):
        # Handle Ctrl+C and Russian Ctrl+С
        if event.state & 4 and (event.keysym.lower() in ('c', 'с') or getattr(event, 'keycode', 0) == 67):
            return copy_selection()
        return None

    output_box.bind("<KeyPress>", handle_output_keypress)

    output_menu = tk.Menu(root, tearoff=0)
    output_menu.add_command(label="Copy Selected", command=copy_selection)
    output_menu.add_command(label="Copy All", command=copy_all)
    output_box.bind("<Button-3>", lambda e: output_menu.tk_popup(e.x_root, e.y_root))

    status_var = tk.StringVar(value="Ready")
    status = ttk.Label(root, textvariable=status_var, anchor="w", foreground="#6B7280")
    status.grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 12))

    root.mainloop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract raw VLESS links from a subscription URL.")
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
