import json
import logging
import re
import warnings

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(name=__name__)


class WappalyzerError(Exception):
    """
    Raised for fatal Wappalyzer errors.
    """
    pass


class WebPage(object):
    """
    Simple representation of a web page, decoupled
    from any particular HTTP library's API.
    """

    def __init__(self, response):
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

        self.url = response.url
        self.html = response.text
        self.headers = response.headers
        self.cookies = response.cookies
        try:
            self.headers.keys()
        except AttributeError:
            raise ValueError("Headers must be a dictionary-like object")

        self._parse_html()

    def _parse_html(self):
        """
        Parse the HTML with BeautifulSoup to find <script> and <meta> tags.
        """
        self.parsed_html = soup = BeautifulSoup(self.html, 'html.parser')
        self.scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                'meta', attrs=dict(name=True, content=True))
        }

    @classmethod
    def new_from_url(cls, url, verify=True):
        """
        Constructs a new WebPage object for the URL,
        using the `requests` module to fetch the HTML.

        Parameters
        ----------

        url : str
        verify: bool
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            "Connection": "keep-alive",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            "Accept-Language": "zh-CN,zh;q=0.8",
            # 'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        response = requests.get(url, verify=verify, headers=headers, timeout=5)
        return cls(response)

    # @classmethod
    # def new_from_response(cls, response):
    #     """
    #     Constructs a new WebPage object for the response,
    #     using the `BeautifulSoup` module to parse the HTML.
    #
    #     Parameters
    #     ----------
    #
    #     response : requests.Response object
    #     """
    #     return cls(response.url, html=response.text, headers=response.headers)


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

        for name, app in self.apps.items():
            self._prepare_app(app)

    @classmethod
    def latest(cls, apps_file=None):
        """
        Construct a Wappalyzer instance using a apps db path passed in via
        apps_file, or alternatively the default in data/apps.json
        """
        if apps_file:
            with open(apps_file, 'r') as fd:
                obj = json.load(fd)
        else:
            from httpcheck.wappalyzer.app_json import apps_dict
            # fp = open("Worker/WebCheck/wappalyzer/data/apps.json", encoding='utf-8')
            obj = apps_dict

        return cls(categories=obj['categories'], apps=obj['apps'])

    def _prepare_app(self, app):
        """
        Normalize app data, preparing it for the detection phase.
        """

        # Ensure these keys' values are lists
        for key in ['url', 'html', 'script', 'implies']:
            try:
                value = app[key]
            except KeyError:
                app[key] = []
            else:
                if not isinstance(value, list):
                    app[key] = [value]

        # Ensure these keys exist
        for key in ['cookies', 'js', 'headers', 'meta']:
            try:
                value = app[key]
            except KeyError:
                app[key] = {}

        # Ensure the 'meta' key is a dict
        obj = app['meta']
        if not isinstance(obj, dict):
            app['meta'] = {'generator': obj}

        # Ensure keys are lowercase
        for key in ['cookies', 'headers', 'meta']:
            obj = app[key]
            app[key] = {k.lower(): v for k, v in obj.items()}

        # Prepare regular expression patterns
        for key in ['url', 'html', 'script']:
            app[key] = [self._prepare_pattern(pattern) for pattern in app[key]]

        for key in ['cookies', 'js', 'headers', 'meta']:
            obj = app[key]
            for name, pattern in obj.items():
                obj[name] = self._prepare_pattern(obj[name])

    def _prepare_pattern(self, pattern):
        """
        Strip out key:value pairs from the pattern and compile the regular
        expression.
        """

        regex, _, rest = pattern.partition('\\;')
        if rest.find('version') >= 0:
            version = rest[8:]
        else:
            version = None
        try:
            return re.compile(regex, re.I), version
        except re.error as e:
            warnings.warn(
                "Caught '{error}' compiling regex: {regex}"
                    .format(error=e, regex=regex)
            )
            # regex that never matches:
            # http://stackoverflow.com/a/1845097/413622
            return re.compile(r'(?!x)x'), version

    def _has_app(self, app, webpage):
        """
        Determine whether the web page matches the app signature.
        """
        # Search the easiest things first and save the full-text search of the
        # HTML for last
        for name, regex_version_tuple in app['cookies'].items():
            regex = regex_version_tuple[0]
            version = regex_version_tuple[1]
            if name in webpage.cookies:
                content = webpage.cookies[name]
                if version is None:
                    if regex.search(content):
                        return True, None
                else:
                    version_list = regex.findall(content)
                    if len(version_list) > 0:
                        return True, version_list[0]

        for name, regex_version_tuple in app['headers'].items():
            regex = regex_version_tuple[0]
            version = regex_version_tuple[1]
            if name in webpage.headers:
                content = webpage.headers[name]
                if version is None:
                    if regex.search(content):
                        return True, None
                else:
                    version_list = regex.findall(content)
                    if len(version_list) > 0:
                        return True, version_list[0]

        for regex_version_tuple in app['html']:
            regex = regex_version_tuple[0]
            version = regex_version_tuple[1]
            if version is None:
                if regex.search(webpage.html):
                    return True, None
            else:
                version_list = regex.findall(webpage.html)
                if len(version_list) > 0:
                    return True, version_list[0]

        for regex_version_tuple in app['url']:
            regex = regex_version_tuple[0]
            version = regex_version_tuple[1]

            if version is None:
                if regex.search(webpage.url):
                    return True, None
            else:
                version_list = regex.findall(webpage.url)
                if len(version_list) > 0:
                    return True, version_list[0]

        for name, regex_version_tuple in app['meta'].items():
            regex = regex_version_tuple[0]
            version = regex_version_tuple[1]
            if name in webpage.meta:
                content = webpage.meta[name]

                if version is None:
                    if regex.search(content):
                        return True, None
                else:
                    version_list = regex.findall(content)
                    if len(version_list) > 0:
                        return True, version_list[0]

        for regex_version_tuple in app['script']:
            regex = regex_version_tuple[0]
            version = regex_version_tuple[1]
            for script in webpage.scripts:
                if version is None:
                    if regex.search(script):
                        return True, None
                else:
                    version_list = regex.findall(script)
                    if len(version_list) > 0:
                        return True, version_list[0]
        return False, None

    def _get_implied_apps(self, detected_apps):
        """
        Get the set of apps implied by `detected_apps`.
        """

        def __get_implied_apps(apps):
            _implied_apps = set()
            for app, version in apps:
                try:
                    for one in self.apps[app]['implies']:
                        implie, _, _ = one.partition('\\;')
                        _implied_apps.update({(implie, None)})
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
        cat_names = [self.categories.get("%s" % cat_num, "")
                     for cat_num in cat_nums]

        return cat_names

    def analyze(self, webpage):
        """
        Return a list of applications that can be detected on the web page.
        """
        detected_apps = set()

        for app_name, app in self.apps.items():
            flag, version = self._has_app(app, webpage)

            if flag:
                detected_apps.add((app_name, version))
        detected_apps |= self._get_implied_apps(detected_apps)
        detail_apps = []
        for app_name, version in detected_apps:
            app = self.apps.get(app_name)
            app['name'] = app_name
            app['version'] = version
            detail_apps.append(app)

        return detail_apps

    def analyze_with_categories(self, webpage):
        """
        Return a list of applications and categories that can be detected on the web page.
        """
        format_results = []
        detected_apps = self.analyze(webpage)

        for app in detected_apps:
            cat_names = self.get_categories(app.get('name'))
            app["categories"] = cat_names
            data = {
                "name": app.get('name'),
                "version": app.get('version'),
                "icon": app.get('icon'),
                "website": app.get('website'),
                "categories": cat_names
            }
            if data not in format_results:
                format_results.append({
                    "name": app.get('name'),
                    "version": app.get('version'),
                    "icon": app.get('icon'),
                    "website": app.get('website'),
                    "categories": cat_names
                })
        return format_results
