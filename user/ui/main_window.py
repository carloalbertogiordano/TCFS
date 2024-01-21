import tkinter as tk


def modify_button_allign(button, row, column):
    button.grid(row=row, column=column)


class Window:

    def __init__(self, title: str, geometry: str):
        self.window = tk.Tk()
        self.window.title(title)
        self.window.geometry(geometry)

    def add_button(self, text: str, function, row=0, col=0):
        button = tk.Button(self.window, text=text, command=function)
        button.grid(row=row, column=col)
        return button

    def start_window(self):
        self.window.mainloop()

