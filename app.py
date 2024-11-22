import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
from feature import test_phishing_url


def check_link():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Warning", "Please enter a URL first.")
        return

    result = test_phishing_url(url)

    if "safe" in result:
        answer = messagebox.askquestion("Confirmation",
                                        f"\nResult: {result}\nDo you want to continue to {url}?")
        if answer == 'yes':
            webbrowser.open_new_tab(url)
    else:

        continue_answer = messagebox.askquestion("Phishing Alert",
                                                 f"The URL appears to be phishing.\nResult: {result}\nDo you still want to continue to {url}?")
        if continue_answer == 'yes':
            webbrowser.open_new_tab(url)


root = tk.Tk()
root.title("Web Browser with Phishing Detection")


root.geometry('800x600')
root.configure(bg='#18D79D')


style = ttk.Style()
style.theme_use('default')
style.configure('Custom.TEntry', padding=5, relief=tk.FLAT, borderwidth=2, bordercolor='#d9d9d9', fieldbackground='#ffffff')


url_label = tk.Label(root, text="Search or type URL", font=('Arial', 14), bg='#f5f5f5')
url_label.pack(pady=10)

url_entry = ttk.Entry(root, width=80, font=('Arial', 14), style='Custom.TEntry')
url_entry.pack(pady=10)


check_button = tk.Button(root, text="Search", command=check_link, bg='#4285f4', fg='white', font=('Arial', 14), relief=tk.FLAT, width=10, bd=0, pady=8)
check_button.pack(pady=10)


canvas = tk.Canvas(root, bg='#f5f5f5', height=400, width=800)
canvas.pack(pady=20)

card_frame = tk.Frame(canvas, bg='white', highlightthickness=2, highlightbackground='#d9d9d9', padx=20, pady=20)
card_frame.place(relx=0.5, rely=0.5, anchor='center')

info_label = tk.Label(card_frame, text="Phishing Detection Education:\n\n"
                                       "Phishing is a fraudulent attempt to obtain sensitive information such as usernames, passwords,\n"
                                       "and credit card details by disguising as a trustworthy entity in an electronic communication.\n\n"
                                       "Advantages of using this site:\n"
                                       "- Advanced Phishing Detection Algorithm\n"
                                       "- Secure Browsing Experience\n"
                                       "- Real-time URL Analysis\n\n"
                                       "Why use this site?\n"
                                       "Our site uses state-of-the-art machine learning techniques to identify phishing links and\n"
                                       "provides a secure environment for your browsing.\n\n"
                                       "Stay Safe Online!", font=('Arial', 12), bg='white')
info_label.pack()



footer_frame = tk.Frame(root, bg='#4285f4', height=30)
footer_frame.pack(side=tk.BOTTOM, fill=tk.X)


footer_label = tk.Label(footer_frame, text="© 2023 pshining detection api. All rights reserved.", font=('Arial', 10), bg='#4285f4', fg='white')
footer_label.pack()

root.mainloop()
