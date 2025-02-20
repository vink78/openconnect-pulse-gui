#!/usr/bin/env python3

import json
import gi
from cryptography.fernet import Fernet

import argparse
import logging
import os
import errno
import base64

try:
    import queue
except ImportError:
    import Queue as queue
import subprocess
import sys
import time
import threading

try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, WebKit2, GLib

# File to save form data
DATA_FILE = os.path.expanduser("~/.local/openconnect_data.json")
KEY_FILE = os.path.expanduser("~/.local/secret.key")

# Generate an encryption key
def load_or_generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

key = load_or_generate_key()
fernet = Fernet(key)

# Encrypt all fields which contain 'pass'
def encrypt_sensitive_data(data):
    for field in data:
        if "pass" in field.lower():  # Check if "pass" is on field name
            data[field] = base64.b64encode(fernet.encrypt(data[field].encode())).decode()
    return data

# Decrypt all fields which contain 'pass'
def decrypt_sensitive_data(data):
    for field in data:
        if "pass" in field.lower():
            try:
                data[field] = fernet.decrypt(base64.b64decode(data[field])).decode()
            except Exception as e:
                print(f"❌Decryption error for {field}: {e}")
                data[field] = "Error"
    return data

# Load all saved data
def load_saved_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
            return decrypt_sensitive_data(data)
    return {}

# Save all data, and, encrypt sensitive data
def save_form_data(new_data):
    'Save all forms data'
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

    saved_data = load_saved_data()
    saved_data.update(new_data)
    saved_data = encrypt_sensitive_data(saved_data)

    with open(DATA_FILE, "w") as f:
        json.dump(saved_data, f, indent=4)


log = logging.getLogger("pulsegui")

class PulseLoginView:
    def __init__(
        self,
        uri,
        html=None,
        verbose=False,
        cookies=None,
        verify=True,
        session_cookie_name="DSID",
    ):
        self._window = Gtk.Window().new(Gtk.WindowType.TOPLEVEL)

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.1

        uri_obj = urlparse(uri)._replace(scheme="https")
        uri = urlunparse(uri_obj)

        self.closed = False
        self.user_closed = False
        self.success = False
        self.verbose = verbose
        self.auth_cookie = None
        self._session_cookie_name = session_cookie_name

        self._ctx = WebKit2.WebContext.get_default()
        self._WebSiteDataManager = self._ctx.get_website_data_manager()
        # self._WebSiteDataManager.set_persistent_credential_storage_enabled(True) 
        log.debug(f"Persistent credential storage enabled: {self._WebSiteDataManager.get_persistent_credential_storage_enabled()}")
        log.debug(f"WebSiteDataManager is ephemeral: {self._WebSiteDataManager.props.is_ephemeral}")
        if not verify:
            self._ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)

        self._cookies = self._ctx.get_cookie_manager()
        self._cookies.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
        if cookies:
            log.info("Saving cookies to %s", cookies)
            self._cookies.set_persistent_storage(
                cookies, WebKit2.CookiePersistentStorage.SQLITE
            )

        self._webview = WebKit2.WebView()
        self._webview.connect("load-failed-with-tls-errors", self._tls_error, None)
        self._webview.connect("load-changed", self._on_load_changed)

        self._window.add(self._webview)
        self._window.set_title("Ivanti Connect Secure Login")
        self._window.connect("delete-event", self._user_close)
        self._window.connect("destroy", self._close)
        self._webview.connect("resource-load-started", self._log_request)
        self._cookies.connect("changed", self._cookie_changed)
        
        # self._wvSettings=self._webview.get_settings()
        # log.debug(f"Private browsing enabled: {self._wvSettings.get_enable_private_browsing()}")

        self._window.show_all()
        self._setWindowSize(1300, 600)

        self._request_id = 0

        if html:
            self._webview.load_html(html, uri)
        else:
            self._webview.load_uri(uri)
            
    def _on_load_changed(self, webview, load_event):
        'Inject a JavaScript after page load'
        if load_event == WebKit2.LoadEvent.FINISHED:
            saved_data = load_saved_data()

            js_fill = f"""
            (function() {{
                let savedData = {json.dumps(saved_data)};
                for (let key in savedData) {{
                    let input = document.querySelector(`[name="${{key}}"]`);
                    if (input) input.value = savedData[key];
                }}
            }})();
            """
            webview.evaluate_javascript(script=js_fill, length=len(js_fill), world_name=None, source_uri=None, cancellable=None, callback=None)

            # Intercept form submit to save data
            js_capture = """
            (function() {
                document.addEventListener('submit', function(event) {
                    let formData = {};
                    new FormData(event.target).forEach((value, key) => {
                        formData[key] = value;
                    });
                    window.webkit.messageHandlers.external.postMessage(JSON.stringify(formData));
                }, true);
            })();
            """
            webview.evaluate_javascript(script=js_capture, length=len(js_capture), world_name=None, source_uri=None, cancellable=None, callback=None)

            # Connect WebKit2 to a Python function to store dataset
            manager = self._webview.get_user_content_manager()
            manager.register_script_message_handler("external")
            manager.connect("script-message-received::external", self._on_form_submit)

    def _on_form_submit(self, user_content_manager, message):
        'Save form data'
        print("✅ Save all forms data.")
        data = json.loads(message.get_js_value().to_string())

        save_form_data(data)

    def _getCurrentMonitorGeometry(self):
        'Return the geometry of the monitor on which self._window is shown.'
        display=self._window.get_display()
        GdkWindow=self._window.get_window()
        if GdkWindow is None: # The window is not realized, yet
            currentMonitor=display.get_monitor(0) # Just pick the first available monitor
        else:
            currentMonitor=display.get_monitor_at_window(self._window.get_window())
        return currentMonitor.get_geometry()
    
    def _setWindowSize(self, width, height):
        '''
            Set size of self._window to width x height,
            but not larger than the monitor self._window is displayed on.
        '''
        currentMonitorGeometry=self._getCurrentMonitorGeometry()
        if width > currentMonitorGeometry.width:
            width = currentMonitorGeometry.width
        if height > currentMonitorGeometry.height:
           height = currentMonitorGeometry.height
        self._window.resize(width, height)

    def _user_close(self, *args, **kwargs):
        self.user_closed = True
        self._close()

    def _close(self, *args, **kwargs):
        if not self.closed:
            self.closed = True
            log.info("closing GTK")
            # time.sleep(.1)
            Gtk.main_quit()

    def _log_request(self, webview, resource, request):
        request_id = self._request_id
        self._request_id += 1
        # log.debug(
        # "[REQ  %d] %s %s"
        # , request_id, request.get_http_method() or "Request", resource.get_uri(),
        # )
        # if self.verbose > 2:
        resource.connect("finished", self._log_resource_details, (request_id, request))
        resource.connect("sent-request", self._log_sent_request, (request_id, request))

    def _tls_error(self, webview, failing_uri, certificate, errors, user_data):
        log.error(
            "TLS error on {} : {}. Use --insecure to bypass certificate validation.".format(
                failing_uri, ", ".join(errors.value_nicks)
            )
        )

    def _log_sent_request(self, resource, request, redirected_response, userdata):
        request_id, request = userdata
        if redirected_response:
            status_code = redirected_response.get_status_code()
            old_uri = redirected_response.get_uri()
            new_uri = resource.get_uri()
            log.debug(
                "[REQ2 %d] %s redirect from %s to %s", request_id, status_code, old_uri, new_uri
            )
        else:
            method = request.get_http_method() or "Request"
            request_uri = request.get_uri()
            log.debug("[REQ2 %d] %s %s", request_id, method, request_uri)

    def _log_resource_details(self, resource, userdata):
        request_id, request = userdata
        method = request.get_http_method() or "Request"
        uri = resource.get_uri()
        response = resource.get_response()
        if not response:
            return
        status_code = response.get_status_code()
        content_type = response.get_mime_type()
        content_length = response.get_content_length()
        content_details = "%d bytes of %s" % (content_length, content_type,)
        log.debug("[RESP %d] %s: %s", request_id, status_code, content_details)

    def log_resource_text(
        self, resource, result, content_type, charset=None, show_headers=None
    ):
        data = resource.get_data_finish(result)
        content_details = "%d bytes of %s%s for " % (
            len(data),
            content_type,
            ("; charset=" + charset) if charset else "",
        )
        log.info(
            "[DATA   ] %sresource %s", content_details, resource.get_uri(),
        )
        if show_headers:
            for h, v in show_headers.items():
                print("%s: %s" % (h, v), file=sys.stderr)
            print(file=sys.stderr)
        if charset or content_type.startswith("text/"):
            print(data.decode(charset or "utf-8"), file=sys.stderr)        

    def _cookie_changed(self, event):
        uri = self._webview.get_uri()
        #if self.verbose:
        #  print(event, uri)
        self._cookies.get_cookies(uri, None, self._check_for_authcookie, uri)

    def _check_for_authcookie(self, source_object, res, uri):
        cookies = source_object.get_cookies_finish(res)
        for cookie in cookies:
            #            print(
            #                " ",
            #                cookie.get_name(),
            #                cookie.get_value(),
            #                cookie.get_domain(),
            #                cookie.get_path(),
            #                cookie.get_expires(),
            #                cookie.get_secure(),
            #                cookie.get_http_only()
            #            )
            if cookie.get_name() == self._session_cookie_name:
                if not self.success:
                    # Only call destroy once
                    self.auth_cookie = cookie
                    self.success = True
                    log.info("Got auth cookie")
                    self._window.destroy()


def parse_args(args=None, prog=None):
    p = argparse.ArgumentParser(prog=prog)
    p.add_argument("server", help="Pulse Secure Connect URL")
    p.add_argument(
        "--insecure", action="store_true", help="Ignore invalid server certificate",
    )
    p.add_argument(
        "--session-cookie-name",
        default="DSID",
        help=argparse.SUPPRESS,  # "Name of the session cookie (default: %(default)s)"
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-v",
        "--verbose",
        default=0,
        action="count",
        help="Increase verbosity of explanatory output to stderr",
    )
    x.add_argument(
        "-q",
        "--quiet",
        dest="verbose",
        action="store_const",
        const=0,
        help="Reduce verbosity to a minimum",
    )

    # The functionality for saving non-session cookies exists
    # however, it is hidden from help due to security concerns.
    #
    # Note that if you use this, cookies will be saved in PLAIN TEXT.
    #
    # This could be worked around by implementing the Soup.CookieJar
    # interface in a secure manner
    #
    p.add_argument(
        "-p",
        "--persist-cookies",
        action="store_true",
        help=argparse.SUPPRESS,  # "Save non-session cookies to disk",
    )
    p.add_argument(
        "-c",
        "--cookie-file",
        default="~/.config/pulse-gui-cookies",
        help=argparse.SUPPRESS,  # "Store cookies in this file (instead of default %(default)s)",
    )
    args = p.parse_args(args=None)

    if args.persist_cookies and args.cookie_file:
        args.cookie_file = os.path.expanduser(args.cookie_file)

    return p, args


def do_openconnect(server, authcookie, run_openconnect=False):
    cmd = [
        "sudo",
        "openconnect",
        "--protocol",
        "nc",
        "-C",
        f'{authcookie.get_name()}={authcookie.get_value()}',
        server,
    ]
    if not run_openconnect:
        print(" ".join(cmd))
        return None
    else:
        print("Now running '", " ".join(cmd), "'")
        proc = subprocess.Popen(cmd)
        print(proc)
        ret = proc.wait()
        return ret


def saml_thread(jobQ, returnQ, closeEvent):
    while not closeEvent.is_set():
        try:
            job = jobQ.get(block=False)
        except queue.Empty:
            time.sleep(0.1)
            continue
        slv = PulseLoginView(
            job.server,
            verbose=job.verbose,
            cookies=job.cookie_file if job.persist_cookies else None,
            verify=not job.insecure,
            session_cookie_name=job.session_cookie_name,
        )
        Gtk.main()
        if slv.user_closed:
            returnQ.put({"error": "Login window closed by user", "retry": False})
        elif not slv.success:
            returnQ.put(
                {
                    "error": "Login window closed without producing session cookie",
                    "retry": True
                }
            )
        else:
            returnQ.put({"auth_cookie": slv.auth_cookie, "retry": False})


def main(prog=None):
    p, args = parse_args(prog=prog)

    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    if args.verbose > 2:
        log_level = log_levels[-1]
    else:
        log_level = log_levels[args.verbose]
    logging.basicConfig(level=log_level)

    run_openconnect = True

    if os.geteuid() == 0:
        log.error(
            " You should not run this script as root. Please configure sudo to allow access to openconnect."
        )
        run_openconnect = False
        exit(0)

    # Create a thread for GTK handling
    # This allows us to do things in the main python thread (e.g. catch SIGINT)

    # closeEvent signals to Gtk thread that it should immediately stop
    # when closeEvent is used, the main python thread calls Gtk.main_quit()

    jobQ = queue.Queue()
    returnQ = queue.Queue()
    closeEvent = threading.Event()

    webkitthread = threading.Thread(
        target=saml_thread, args=(jobQ, returnQ, closeEvent)
    )
    webkitthread.start()

    errCount = 1
    errMaxCount = 3
    while True:
        try:
            jobQ.put(args)
            ret = returnQ.get()
            if "error" in ret:
                log.error(ret["error"])
                if not ret["retry"]:
                    break
                time.sleep(0.5)
                continue

            # extract response and convert to OpenConnect command-line
            exit_code = do_openconnect(
                args.server, ret["auth_cookie"], run_openconnect=run_openconnect
            )

            # Exit codes from openconnect/main.c
            if (exit_code == 0 or # success
            exit_code == errno.EPERM or # Server terminated connection
            exit_code == errno.EPIPE or # Cookie was rejected by server
            exit_code == errno.EINTR or # User cancelled
            exit_code is None):
                break

        except KeyboardInterrupt:
            log.warning("User exited")
            Gtk.main_quit()
            break
        else:
            if errCount > errMaxCount:
                log.warning(f"openconnect failed to establish connection {errMaxCount:d} times. Aborting.")
                break
            log.info(f"openconnect failed to establish connection with exit code {exit_code:d}. Retrying..")
            errCount += 1
            time.sleep(1)

    closeEvent.set()
    webkitthread.join()


if __name__ == "__main__":
    main()
