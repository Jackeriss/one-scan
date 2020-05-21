import json
import re
import warnings
import os

import requests
from bs4 import BeautifulSoup

from app.util.config_util import config
from app.constant.constant import UNKNOWN


__plugin__ = "Technology Scanner"
SEQUENCE = 5


APP_FILE_PATH = os.path.join(config.base_dir, "plugin", "data", "apps.json")
DEFAULT_ICON_IMAGE = ""


class WebPage(object):
    """
    Simple representation of a web page, decoupled
    from any particular HTTP library's API.
    """

    def __init__(self, url, html, headers):
        """
        Initialize a new WebPage object.

        Parameters
        ----------

        url : str
            The web page URL.
        html : str
            The web page content (HTML)
        headers : dict
            The HTTP response headers
        """
        self.url = url
        self.html = html
        self.headers = headers

        try:
            self.headers.keys()
        except AttributeError:
            raise ValueError("Headers must be a dictionary-like object")

        self._parse_html()

    def _parse_html(self):
        """
        Parse the HTML with BeautifulSoup to find <script> and <meta> tags.
        """
        self.parsed_html = soup = BeautifulSoup(self.html, "lxml")
        self.scripts = [script["src"] for script in soup.findAll("script", src=True)]
        self.meta = {
            meta["name"].lower(): meta["content"]
            for meta in soup.findAll("meta", attrs=dict(name=True, content=True))
        }

    @classmethod
    def new_from_url(cls, url, timeout):
        """
        Constructs a new WebPage object for the URL,
        using the `requests` module to fetch the HTML.
        Parameters
        ----------
        url : str
        timeout: int
        """
        response = requests.get(url, verify=False, timeout=timeout)
        return cls.new_from_response(response)

    @classmethod
    def new_from_response(cls, response):
        """
        Constructs a new WebPage object for the response,
        using the `BeautifulSoup` module to parse the HTML.

        Parameters
        ----------

        response : requests.Response object
        """
        return cls(response.url, html=response.text, headers=response.headers)


class Wappalyzer(object):
    """
    Python Wappalyzer driver.
    """

    def __init__(self, categories, apps):
        """
        Initialize a new Wappalyzer instance.

        Parameters
        ----------

        categories : dict
            Map of category ids to names, as in apps.json.
        apps : dict
            Map of app names to app dicts, as in apps.json.
        """
        self.categories = categories
        self.apps = apps

        for _, app in self.apps.items():
            self._prepare_app(app)

    @classmethod
    def latest(cls, apps_file=None):
        """
        Construct a Wappalyzer instance using a apps db path passed in via
        apps_file, or alternatively the default in data/apps.json
        """
        if apps_file:
            with open(apps_file, "r") as default_file:
                obj = json.load(default_file)
        else:
            apps_file_name = os.path.join(
                config.base_dir, "plugin", "data", "apps.json"
            )
            with open(apps_file_name, "r") as apps:
                obj = json.load(apps)

        return cls(categories=obj["categories"], apps=obj["apps"])

    def _prepare_app(self, app):
        """
        Normalize app data, preparing it for the detection phase.
        """

        # Ensure these keys' values are lists
        for key in ["url", "html", "script", "implies"]:
            try:
                value = app[key]
            except KeyError:
                app[key] = []
            else:
                if not isinstance(value, list):
                    app[key] = [value]

        # Ensure these keys exist
        for key in ["headers", "meta"]:
            try:
                value = app[key]
            except KeyError:
                app[key] = {}

        # Ensure the 'meta' key is a dict
        obj = app["meta"]
        if not isinstance(obj, dict):
            app["meta"] = {"generator": obj}

        # Ensure keys are lowercase
        for key in ["headers", "meta"]:
            obj = app[key]
            app[key] = {k.lower(): v for k, v in obj.items()}

        # Prepare regular expression patterns
        for key in ["url", "html", "script"]:
            app[key] = [self._prepare_pattern(pattern) for pattern in app[key]]

        for key in ["headers", "meta"]:
            obj = app[key]
            for name, pattern in obj.items():
                obj[name] = self._prepare_pattern(obj[name])

    def _prepare_pattern(self, pattern):
        """
        Strip out key:value pairs from the pattern and compile the regular
        expression.
        """
        regex, _, _ = pattern.partition("\\;")
        try:
            return re.compile(regex, re.I)
        except re.error as err:
            warnings.warn(
                "Caught '{error}' compiling regex: {regex}".format(
                    error=err, regex=regex
                )
            )
            # regex that never matches:
            # http://stackoverflow.com/a/1845097/413622
            return re.compile(r"(?!x)x")

    def _has_app(self, app, webpage):
        """
        Determine whether the web page matches the app signature.
        """
        # Search the easiest things first and save the full-text search of the
        # HTML for last

        for regex in app["url"]:
            if regex.search(webpage.url):
                return True
        for name, regex in app["headers"].items():
            if name in webpage.headers:
                content = webpage.headers[name]
                if regex.search(content):
                    return True

        for regex in app["script"]:
            for script in webpage.scripts:
                if regex.search(script):
                    return True

        for name, regex in app["meta"].items():
            if name in webpage.meta:
                content = webpage.meta[name]
                if regex.search(content):
                    return True

        for regex in app["html"]:
            if regex.search(webpage.html):
                return True

    def _get_implied_apps(self, detected_apps):
        """
        Get the set of apps implied by `detected_apps`.
        """

        def __get_implied_apps(apps):
            _implied_apps = set()
            for app in apps:
                try:
                    _implied_apps.update(set(self.apps[app]["implies"]))
                except KeyError:
                    pass
            return _implied_apps

        implied_apps = __get_implied_apps(detected_apps)
        all_implied_apps = set()

        # Descend recursively until we've found all implied apps
        while not all_implied_apps.issuperset(implied_apps):
            all_implied_apps.update(implied_apps)
            implied_apps = __get_implied_apps(all_implied_apps)

        return all_implied_apps

    def get_categories(self, app_name):
        """
        Returns a list of the categories for an app name.
        """
        cat_nums = self.apps.get(app_name, {}).get("cats", [])
        categories = [self.categories.get("%s" % cat_num, "") for cat_num in cat_nums]

        return categories

    def analyze(self, webpage):
        """
        Return a list of applications that can be detected on the web page.
        """
        detected_apps = set()

        for app_name, app in self.apps.items():
            if self._has_app(app, webpage):
                detected_apps.add(app_name)

        detected_apps |= self._get_implied_apps(detected_apps)

        return detected_apps

    def analyze_with_categories(self, webpage):
        detected_apps = self.analyze(webpage)
        category_map = {}

        for app_name in detected_apps:
            app_result = {
                "name": app_name,
                "image": self.apps.get(app_name, {}).get("icon", DEFAULT_ICON_IMAGE),
                "url": self.apps.get(app_name, {}).get("website", ""),
            }
            categories = self.get_categories(app_name)
            for category in categories:
                category_map[category["name"]] = {
                    "name": category["name"],
                    "sequence": category["priority"],
                    "result": [],
                }
                category_map[category["name"]]["result"].append(app_result)

        return category_map


SCANNER = Wappalyzer.latest(apps_file=APP_FILE_PATH)


def run(url):
    scan_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result["result"] = [
        {"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}
    ]

    webpage = WebPage.new_from_url(url.geturl(), timeout=5)
    try:
        webpage = WebPage.new_from_url(url.geturl(), timeout=5)
        result_map = SCANNER.analyze_with_categories(webpage) or {
            "": {"name": "Technology", "sequence": 0, "result": [{"name": UNKNOWN}]}
        }
    except:
        return error_result

    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
