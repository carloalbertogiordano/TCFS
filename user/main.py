from ui.main_window import Window


def foo():
    print("Hello World")


win = Window("TCFS user helper", "200x200")

init_env_butt = win.add_button("Initialize the environment", foo, row=0, col=0) #init enviroinment
mount_butt = win.add_button("Mount TCFS", foo, row=1, col=0) #mount tcfs
umount_butt = win.add_button("Umount TCFS", foo, row=2, col=0) #umount
shared_butt = win.add_button("Threshold share", foo, row=3, col=0) #create shared file
logout_butt = win.add_button("Logout", foo, row=4, col=0) #logout


win.start_window()