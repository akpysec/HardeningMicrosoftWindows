import sys
import tkinter
from tkinter import ttk
from tkinter import font as tk_font
from tkinter import filedialog
from ttkwidgets import CheckboxTreeview


def main():
    window = tkinter.Tk()
    window.title('Registry Checker')
    window.geometry('500x350')
    window['padx'] = 8
    # window.iconbitmap(default="Appwheel.ico")
    title_font = tk_font.Font(family='Arial', size=10, weight="bold")
    label1 = ttk.Label(text="Check the boxes:", font=title_font)
    label1.grid(row=0, column=0, sticky="nw", pady=8)

    window.grid_columnconfigure(0, weight=1)
    window.grid_columnconfigure(1, weight=1)
    window.grid_columnconfigure(2, weight=1)
    window.grid_columnconfigure(3, weight=1)
    window.grid_columnconfigure(4, weight=1)
    window.grid_rowconfigure(0, weight=5)
    window.grid_rowconfigure(1, weight=1)
    window.grid_rowconfigure(2, weight=1)
    window.grid_rowconfigure(3, weight=1)
    window.grid_rowconfigure(4, weight=10)

    button1 = ttk.Button(text="Next", command=None)
    button1.grid(row=4, column=5, sticky='es', padx=10, pady=10)

    button2 = ttk.Button(text="Quit", command=sys.exit)
    button2.grid(row=4, column=0, sticky='ws', padx=10, pady=10)

    radio_button1 = ttk.Radiobutton(text="test1")
    radio_button1.grid(row=1, column=0, sticky='ws', padx=5, pady=5)

    radio_button2 = ttk.Radiobutton(text="test2")
    radio_button2.grid(row=2, column=0, sticky='ws', padx=5, pady=5)

    radio_button3 = ttk.Radiobutton(text="test3")
    radio_button3.grid(row=3, column=0, sticky='ws', padx=5, pady=5)

    window.mainloop()


main()
