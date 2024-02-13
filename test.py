import re
import urllib.parse
import whois
from datetime import date
import ipaddress
import numpy as np
import pandas as pd
import joblib  # Import joblib instead of pickle
import re
import urllib.parse
import whois
from datetime import date
import ipaddress

from sklearn import ensemble


class FeatureExtraction:
        def __init__(self, url):
            self.url = url
            self.domain = urllib.parse.urlparse(url).netloc
            self.whois_response = None
            self.features = []

        def extract_features(self):

            self.features.append(self.using_ip())
            self.features.append(self.long_url())
            self.features.append(self.short_url())
            self.features.append(self.symbol())
            self.features.append(self.redirecting())
            self.features.append(self.prefix_suffix())
            self.features.append(self.sub_domains())
            self.features.append(self.https())
            self.features.append(self.domain_reg_len())
            self.features.append(self.favicon())
            self.features.append(self.non_std_port())
            self.features.append(self.https_domain_url())
            self.features.append(self.request_url())
            self.features.append(self.anchor_url())
            self.features.append(self.links_in_script_tags())
            self.features.append(self.server_form_handler())
            self.features.append(self.info_email())
            self.features.append(self.abnormal_url())
            self.features.append(self.website_forwarding())
            self.features.append(self.status_bar_cust())
            self.features.append(self.disable_right_click())
            self.features.append(self.using_popup_window())
            self.features.append(self.iframe_redirection())
            self.features.append(self.age_of_domain())
            self.features.append(self.dns_recording())
            self.features.append(self.website_traffic())
            self.features.append(self.page_rank())
            self.features.append(self.google_index())
            self.features.append(self.links_pointing_to_page())
            self.features.append(self.stats_report())

            return self.features

        # Feature extraction methods
        def using_ip(self):
            try:
                ipaddress.ip_address(self.url)
                return -1
            except ValueError:
                return 1

        def long_url(self):
            if len(self.url) < 54:
                return 1
            elif 54 <= len(self.url) <= 75:
                return 0
            else:
                return -1

        def short_url(self):
            match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                              r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                              r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                              r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                              r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                              r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                              r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                              self.url)
            if match:
                return -1
            else:
                return 1

        def symbol(self):
            if re.findall("@", self.url):
                return -1
            else:
                return 1

        def redirecting(self):
            if self.url.rfind('//') > 6:
                return -1
            else:
                return 1

        def prefix_suffix(self):
            match = re.findall('\-', self.domain)
            if match:
                return -1
            else:
                return 1

        def sub_domains(self):
            dot_count = len(re.findall("\.", self.url))
            if dot_count == 1:
                return 1
            elif dot_count == 2:
                return 0
            else:
                return -1

        def https(self):
            try:
                https = urllib.parse.urlparse(self.url).scheme
                if 'https' in https:
                    return 1
                else:
                    return -1
            except:
                return 1

        def domain_reg_len(self):
            try:
                whois_info = whois.whois(self.domain)
                expiration_date = whois_info.expiration_date
                creation_date = whois_info.creation_date

                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                age_in_months = (expiration_date.year - creation_date.year) * 12 + (
                            expiration_date.month - creation_date.month)

                if age_in_months >= 12:
                    return 1
                else:
                    return -1
            except:
                return -1

        def favicon(self):
            try:
                for head in self.soup.find_all('head'):
                    for link in head.find_all('link', href=True):
                        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                        if self.url in link['href'] or len(dots) == 1 or self.domain in link['href']:
                            return 1
                return -1
            except:
                return -1

        # Implement the remaining feature extraction methods here

        # Feature extraction methods (continued)
        def non_std_port(self):
            try:
                port = self.domain.split(":")
                if len(port) > 1:
                    return -1
                else:
                    return 1
            except:
                return -1

        def https_domain_url(self):
            try:
                if 'https' in self.domain:
                    return -1
                else:
                    return 1
            except:
                return -1

        def request_url(self):
            try:
                i, success = 0, 0
                for img in self.soup.find_all('img', src=True):
                    dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                    if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                        success = success + 1
                    i = i + 1

                for audio in self.soup.find_all('audio', src=True):
                    dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                    if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                        success = success + 1
                    i = i + 1

                for embed in self.soup.find_all('embed', src=True):
                    dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                    if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                        success = success + 1
                    i = i + 1

                for iframe in self.soup.find_all('iframe', src=True):
                    dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                    if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                        success = success + 1
                    i = i + 1

                try:
                    percentage = success / float(i) * 100
                    if percentage < 22.0:
                        return 1
                    elif (22.0 <= percentage < 61.0):
                        return 0
                    else:
                        return -1
                except:
                    return 0
            except:
                return -1

        def anchor_url(self):
            try:
                i, unsafe = 0, 0
                for a in self.soup.find_all('a', href=True):
                    if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                            self.url in a['href'] or self.domain in a['href']):
                        unsafe = unsafe + 1
                    i = i + 1

                try:
                    percentage = unsafe / float(i) * 100
                    if percentage < 31.0:
                        return 1
                    elif (31.0 <= percentage < 67.0):
                        return 0
                    else:
                        return -1
                except:
                    return -1

            except:
                return -1

        def links_in_script_tags(self):
            try:
                i, success = 0, 0

                for link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                    if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                        success = success + 1
                    i = i + 1

                for script in self.soup.find_all('script', src=True):
                    dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                    if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                        success = success + 1
                    i = i + 1

                try:
                    percentage = success / float(i) * 100
                    if percentage < 17.0:
                        return 1
                    elif (17.0 <= percentage < 81.0):
                        return 0
                    else:
                        return -1
                except:
                    return 0
            except:
                return -1

        def server_form_handler(self):
            try:
                if len(self.soup.find_all('form', action=True)) == 0:
                    return 1
                else:
                    for form in self.soup.find_all('form', action=True):
                        if form['action'] == "" or form['action'] == "about:blank":
                            return -1
                        elif self.url not in form['action'] and self.domain not in form['action']:
                            return 0
                        else:
                            return 1
            except:
                return -1

        def info_email(self):
            try:
                if re.findall(r"[mail\(\)|mailto:?]", self.soup):
                    return -1
                else:
                    return 1
            except:
                return -1

        def abnormal_url(self):
            try:
                if self.response.text == self.whois_response:
                    return 1
                else:
                    return -1
            except:
                return -1

        def website_forwarding(self):
            try:
                if len(self.response.history) <= 1:
                    return 1
                elif 1 < len(self.response.history) <= 4:
                    return 0
                else:
                    return -1
            except:
                return -1

        def status_bar_cust(self):
            try:
                if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                    return 1
                else:
                    return -1
            except:
                return -1

        def disable_right_click(self):
            try:
                if re.findall(r"event.button ?== ?2", self.response.text):
                    return 1
                else:
                    return -1
            except:
                return -1

        def using_popup_window(self):
            try:
                if re.findall(r"alert\(", self.response.text):
                    return 1
                else:
                    return -1
            except:
                return -1

        def iframe_redirection(self):
            try:
                if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                    return 1
                else:
                    return -1
            except:
                return -1

        def age_of_domain(self):
            try:
                whois_info = whois.whois(self.domain)
                creation_date = whois_info.creation_date

                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                today = date.today()
                age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
                if age >= 6:
                    return 1
                else:
                    return -1
            except:
                return -1

        def dns_recording(self):
            try:
                dns = 0
                if self.domain in self.response.text:
                    return 1
                else:
                    return -1
            except:
                return -1

        def website_traffic(self):
            try:
                if re.findall(r"alexa.com/siteinfo/", self.response.text):
                    return -1
                else:
                    return 1
            except:
                return -1

        def page_rank(self):
            try:
                if re.findall(r"google.com/search\?q=info:", self.response.text):
                    return -1
                else:
                    return 1
            except:
                return -1

        def google_index(self):
            try:
                if re.findall(r"Indexed by Google", self.response.text):
                    return 1
                else:
                    return -1
            except:
                return -1

        def links_pointing_to_page(self):
            try:
                num_links = len(re.findall(r"<a href=", self.response.text))
                if num_links == 0:
                    return -1
                elif num_links <= 2:
                    return 0
                else:
                    return 1
            except:
                return -1

        def stats_report(self):
            try:
                if re.findall(r"clicky.com/\"|googlesyndication.com/\"|analytics.google.com/\"", self.response.text):
                    return -1
                else:
                    return 1
            except:
                return -1



        def extract_features(self):
            # Extract features and return the feature vector
            features = [

                self.using_ip(),
                self.long_url(),
                self.short_url(),
                self.symbol(),
                self.redirecting(),
                self.prefix_suffix(),
                self.sub_domains(),
                self.https(),
                self.domain_reg_len(),
                self.favicon(),
                self.non_std_port(),
                self.https_domain_url(),
                self.request_url(),
                self.anchor_url(),
                self.links_in_script_tags(),
                self.server_form_handler(),
                self.info_email(),
                self.abnormal_url(),
                self.website_forwarding(),
                self.status_bar_cust(),
                self.disable_right_click(),
                self.using_popup_window(),
                self.iframe_redirection(),
                self.age_of_domain(),
                self.dns_recording(),
                self.website_traffic(),
                self.page_rank(),
                self.google_index(),
                self.links_pointing_to_page(),
                self.stats_report()
            ]

            return features


        # Your existing FeatureExtraction class and feature extraction methods here



ensemble\
    = joblib.load("train.joblib")  # Replace with your model file name

def test_phishing_url(url_to_test):
    obj = FeatureExtraction(url_to_test)
    features = obj.extract_features()  # Get features as a list

    x = np.array(features).reshape(1, -1)  # Reshape to a 2D array

    y_pred = ensemble.predict(x)[0]
    # 1 is safe, -1 is unsafe
    y_pro_phishing = ensemble.predict_proba(x)[0, 0]
    y_pro_non_phishing = ensemble.predict_proba(x)[0, 1]

    # Additional conditions and explanations
    if y_pred == 1:
        pred = "It is {0:.2f}% safe to go.".format(y_pro_non_phishing * 100)
    else:
        pred = "It is {0:.2f}% unsafe.".format(y_pro_phishing * 100)

        # You can add more conditions here based on your model's predictions
        if y_pro_phishing > 0.75:
            pred += " This URL is highly likely to be phishing."
        elif y_pro_phishing > 0.5:
            pred += " This URL has a moderate chance of being phishing."
        else:
            pred += " This URL may not be phishing, but exercise caution."

    return pred

if __name__ == "__main__":
    url_to_test = input("Enter a URL to test: ")
    result = test_phishing_url(url_to_test)
    print(result)
