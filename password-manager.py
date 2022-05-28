from tkinter import *
import sqlite3, hashlib

#Database Code

with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
 """)


# Initiate windiow
window = Tk()

window.title("Password manager")

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash
def firstScreen():
    window.geometry("400x200")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window,width=20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window,text="re-type password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window,width=20)
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    def SavePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?)
            """
            cursor.execute(insert_password,[(hashedPassword)])
            db.commit()
            passwordValut()
        else:
            lbl2.config(text="wrong Password")

    btn = Button(window, text="Submit" ,command=SavePassword)
    btn.pack(pady=20)

def loginScreen():
    window.geometry("350x150")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window,width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()


    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 and password=?", [(checkHashedPassword)])
        print(checkHashedPassword) 
        return cursor.fetchall()   
    def checkPassword():
        match = getMasterPassword()

        print(match)
        

        if match:
            passwordValut()
        else:
            lbl1.config(text="wrong Password")
            txt.delete(0,'end')

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=20)


def passwordValut():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x350")



cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()