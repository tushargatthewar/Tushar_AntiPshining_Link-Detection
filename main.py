import streamlit as st
import webbrowser
from feature import test_phishing_url

# Streamlit App
st.set_page_config(page_title="Phishing Detection Web App", page_icon="🔍", layout="centered")

st.title("🔍 Web Browser with Phishing Detection")

# URL Entry
url = st.text_input("Search or type URL", value="", max_chars=200, help="Enter the URL you want to check")

if st.button("Search"):
    if not url:
        st.warning("Please enter a URL first.")
    else:
        result = test_phishing_url(url)

        if "safe" in result.lower():
            st.success(f"Result: {result}\n\nThe URL appears to be safe.")
            if st.button("Continue to URL"):
                webbrowser.open_new_tab(url)
                st.info(f"[Click here to open {url}]({url})")
        else:
            st.error(f"The URL appears to be phishing.\n\nResult: {result}")
            if st.button("Proceed Anyway"):
                webbrowser.open_new_tab(url)
                st.info(f"[Click here to open {url}]({url})")

# Information Section (previously canvas & card frame)
st.markdown("""
---  
### 🛡️ Phishing Detection Education:

Phishing is a fraudulent attempt to obtain sensitive information such as usernames, passwords,  
and credit card details by disguising as a trustworthy entity in an electronic communication.

#### Advantages of using this site:
- 🔍 Advanced Phishing Detection Algorithm  
- 🔐 Secure Browsing Experience  
- ⏱️ Real-time URL Analysis  

#### Why use this site?
Our site uses state-of-the-art machine learning techniques to identify phishing links and  
provides a secure environment for your browsing.

**Stay Safe Online!**
""")

# Footer
st.markdown("""
---  
<center>© 2023 Phishing Detection API. All rights reserved.</center>
""", unsafe_allow_html=True)
