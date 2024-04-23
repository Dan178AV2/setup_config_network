import ctypes
import sys
import os
import json
from tkinter import Tk, Canvas, Button, PhotoImage
from utils.ip_server import Ip_utils

def is_admin() -> bool:
    """
    La función `is_admin()` comprueba si el usuario actual tiene privilegios administrativos en un
    sistema Windows.
    :return: 
        La función `is_admin()` devuelve un valor booleano. Intenta verificar si el usuario actual
        tiene privilegios administrativos en un sistema Windows
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def rerun_as_admin():
    """
    Re-run the current python script as admin using the python interpreter
    from `sys.excutable`
    
    Note: it is difficult to get output at the original console.
    """
    ctypes.windll.shell32.ShellExecuteW(
        None,
        u"runas",
        str(sys.executable),
        str(__file__),
        None,
        1
    )

def main():
    interface_instance = interface()
    interface_instance.show()

def path_join(path: str) -> str:
    """
    La función `path_join` toma una ruta y devuelve una ruta absoluta.

    :param path: El parámetro `path` es una cadena que representa una ruta relativa
    :type path: str
    :return: La función `path_join` devuelve una cadena que representa una ruta absoluta
    """
    # Obtén el directorio del script actual
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Usa os.path.join para crear una ruta absoluta
    return os.path.join(current_dir, path)

class interface :
    def __init__(self):
        self.window = Tk()
        self.window.geometry("700x500")
        self.window.configure(bg = "#FBFBFB")
        self.screen_type = 'DHCP'
        self.text_ids = []
        self.canvas = Canvas(
            self.window,
            bg = "#FBFBFB",
            height = 500,
            width = 700,
            bd = 0,
            highlightthickness = 0,
            relief = "ridge"
        )
        # booleans
        self.original_config_enabled = False
        self.dual_camera_config_enabled = False
        self.client_config_enabled = False
        self.server_config_config_enabled = False
        
        # Canvas 
        self.canvas.place(x = 0, y = 0)
        self.canvas.create_text(
            25.0,
            23.0,
            anchor="nw",
            text="Network Settings",
            fill="#000000",
            font=("Inter Bold", 20 * -1)
        )

        self.canvas.create_rectangle(
            25.0,
            63.0,
            675.0,
            437.0,
            fill="#fcfcfc",
            outline="#E8E8E8")
        
        # Set a default screen
        self.dhcp_screen()

        # Buttons
        self.dhcp_button_image = PhotoImage(
            file=path_join("build/assets/frame0/button_1.png"))
        self.dhcp_button = Button(
            image=self.dhcp_button_image,
            borderwidth=0,
            highlightthickness=0,
            command=lambda: self.dhcp_screen(),
            relief="flat"
        )
        self.dhcp_button.place(
            x=46.0,
            y=96.0,
            width=126.0,
            height=32.0
        )
        # self.button_image_2 = PhotoImage(
        #     file=path_join("build/assets/frame0/button_2.png"))
        # self.devices_button = Button(
        #     image=self.button_image_2,
        #     borderwidth=0,
        #     highlightthickness=0,
        #     command=lambda: self.devices_screen(),
        #     relief="flat"
        # )
        # self.devices_button.place(
        #     x=187.0,
        #     y=96.0,
        #     width=139.0,
        #     height=32.0
        # )
        self.cancel_btn_image = PhotoImage(
            file=path_join("build/assets/frame0/button_3.png"))
        self.cancel_btn = Button(
            image=self.cancel_btn_image,
            borderwidth=0,
            highlightthickness=0,
            command=self.save_event,
            relief="flat",
            background="#fbfbfb"
        )
        self.cancel_btn.place(
            x=417.0,
            y=455.0,
            width=120.0,
            height=40.0
        )

        self.save_btn_image = PhotoImage(
            file=path_join("build/assets/frame0/button_4.png"))
        self.save_btn = Button(
            image=self.save_btn_image,
            borderwidth=0,
            highlightthickness=0,
            command=self.cancel_event,
            relief="flat",
            background="#fbfbfb"

        )
        self.save_btn.place(
            x=554.0,
            y=455.0,
            width=120.0,
            height=40.0
        )
        self.ip_utils = Ip_utils()

    def buttons(self):
        # images disabled
        self.origin_option_disabled = PhotoImage(file=path_join("assets/disabled/button_5.png"))
        self.dual_camera_image_disabled = PhotoImage(file=path_join("assets/disabled/button_7.png"))
        self.server_config_image_disabled = PhotoImage(file=path_join("assets/disabled/button_6.png"))
        self.client_image_disabled = PhotoImage(file=path_join("assets/disabled/button_8.png"))
        # images enabled
        self.origin_option_enabled = PhotoImage(file=path_join("assets/enabled/Button.png"))
        self.dual_camera_image_enabled = PhotoImage(file=path_join("assets/enabled/Button-2.png"))
        self.server_config_image_enabled = PhotoImage(file=path_join("assets/enabled/Button-1.png"))
        self.client_image_enabled = PhotoImage(file=path_join("assets/enabled/Button-3.png"))
        
        # ip config 
        # original_config es una opción para configurar la ip de la interfaz de red si esta activa con la imagen origin_option_enabled
        # dual_camera_config debe estar desactivada con la imagen original_config_disabled
        self.original_config_enabled = False
        self.original_config = Button(
            image=self.origin_option_disabled,
            borderwidth=0,
            highlightthickness=0,
            command=self.toggle_original_config,
            relief="flat"
        )
        self.original_config.place(
            x=202.0,
            y=208.0,
            width=120.0,
            height=32.0
        )

        # dual_camera_config es una opción para configurar la ip de la interfaz de red si esta activa con la imagen dual_camera_config_enabled
        # original_config debe estar desactivada con la imagen dual_camera_config_disabled
        self.dual_camera_config_enabled = False
        self.dual_camera_config = Button(
            image=self.dual_camera_image_disabled,
            borderwidth=0,
            highlightthickness=0,
            command=self.toggle_dual_camera_config,
            relief="flat"
        )
        self.dual_camera_config.place(
            x=368.0,
            y=208.0,
            width=120.0,
            height=32.0
        )

        # Config Ip
        # server_config es una opción para configurar la ip de la interfaz de red si esta activa con la imagen server_config_image_enabled
        # client_config debe estar desactivada con la imagen server_config_image_disabled
        self.server_config_config_enabled = False
        self.server_config = Button(
            image=self.server_config_image_disabled,
            borderwidth=0,
            highlightthickness=0,
            command=self.toggle_server_config,
            relief="flat"
        )
        self.server_config.place(
            x=202.0,
            y=311.0,
            width=120.0,
            height=32.0
        )
        # client_config es una opción para configurar la ip de la interfaz de red si esta activa con la imagen client_image_enabled
        # server_config debe estar desactivada con la imagen client_image_disabled
        self.client_config_enabled = False
        self.client_config = Button(
            image=self.client_image_disabled,
            borderwidth=0,
            highlightthickness=0,
            command=self.toggle_client_config,
            relief="flat"
        )
        self.client_config.place(
            x=368.0,
            y=311.0,
            width=120.0,
            height=32.0
        )

    def toggle_original_config(self):
        if not self.original_config_enabled:
            self.original_config.config(image=self.origin_option_enabled)
            self.original_config_enabled = True
            print("original_config enabled")
            self.ip_utils.dhcp_enabled()
            # Desactivar dual_camera_config
            self.dual_camera_config.config(image=self.dual_camera_image_disabled)
            self.dual_camera_config_enabled = False
            self.server_config_config_enabled = False
            self.client_config_enabled = False
            self.client_config.config(image=self.client_image_disabled)
            self.server_config.config(image=self.server_config_image_disabled)

            print("dual_camera_config disabled")
        else:
            self.original_config.config(image=self.origin_option_disabled)
            self.original_config_enabled = False
            print("original_config disabled")

    def toggle_dual_camera_config(self):
        if not self.dual_camera_config_enabled:
            self.dual_camera_config.config(image=self.dual_camera_image_enabled)
            self.dual_camera_config_enabled = True
            print("dual_camera_config enabled")

            # Desactivar original_config
            self.original_config.config(image=self.origin_option_disabled)
            self.original_config_enabled = False
            print("original_config disabled")
        else:
            self.dual_camera_config.config(image=self.dual_camera_image_disabled)
            self.dual_camera_config_enabled = False
            print("dual_camera_config disabled")

    def toggle_server_config(self):
        if not self.server_config_config_enabled:
            self.server_config.config(image=self.server_config_image_enabled)
            self.server_config_config_enabled = True
            print("server_config enabled")
            self.ip_utils.ip_static_server()
            # Desactivar client_config
            self.client_config.config(image=self.client_image_disabled)
            self.client_config_enabled = False
            print("client_config disabled")
        else:
            self.server_config.config(image=self.server_config_image_disabled)
            self.server_config_config_enabled = False
            print("server_config disabled")

    def toggle_client_config(self):
        if not self.client_config_enabled:
            self.client_config.config(image=self.client_image_enabled)
            self.client_config_enabled = True
            print("client_config enabled")

            self.ip_utils.ip_static_client()
            # Desactivar server_config
            self.server_config.config(image=self.server_config_image_disabled)
            self.server_config_config_enabled = False
            print("server_config disabled")
        else:
            self.client_config.config(image=self.client_image_disabled)
            self.client_config_enabled = False
            print("client_config disabled")

    def change_screen(self, screen_type):
        self.screen_type = screen_type
        self.hide_elements(screen_type)


    def dhcp_screen(self):
        self.buttons()
        self.change_screen('DHCP')
        self.text_ids.append(self.canvas.create_text(
            327.0,
            157.0,
            anchor="nw",
            text="IP Config",
            fill="#000000",
            font=("Roboto Bold", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            325.0,
            267.0,
            anchor="nw",
            text="Config IP:",
            fill="#000000",
            font=("Roboto Bold", 14 * -1)
        ))
        self.original_config.place()
        self.server_config.place()
        self.dual_camera_config.place()
        self.client_config.place()


    def devices_screen(self):
        self.change_screen('Devices')
        print('Devices screen')
        self.original_config.place_forget()
        self.server_config.place_forget()
        self.dual_camera_config.place_forget()
        self.client_config.place_forget()
        self.text_Canvas()

    def text_Canvas(self):
        self.rectangle_id = self.canvas.create_rectangle(
            46.0,
            181.0,
            640.0,
            229.0,
            fill="#FBFBFB",
            outline="")
        image = PhotoImage(file=path_join("build/assets/frame0/button_8.png"))
        self.image_1_id = self.canvas.create_image(
            83.0,
            202.0,
            image=image
        )

        self.text_ids.append(self.canvas.create_text(
            137.0,
            195.0,
            anchor="nw",
            text="PC Server",
            fill="#000000",
            font=("RobotoRoman Regular", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            255.0,
            195.0,
            anchor="nw",
            text="AxisComm",
            fill="#000000",
            font=("RobotoRoman Regular", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            380.0,
            195.0,
            anchor="nw",
            text="00:40:8c:fa:18:56",
            fill="#000000",
            font=("RobotoRoman Regular", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            554.0,
            195.0,
            anchor="nw",
            text="190.168.0.1",
            fill="#000000",
            font=("RobotoRoman Regular", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            149.0,
            151.0,
            anchor="nw",
            text="Name",
            fill="#000000",
            font=("RobotoRoman Bold", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            557.0,
            151.0,
            anchor="nw",
            text="Ip Address",
            fill="#000000",
            font=("RobotoRoman Bold", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            267.0,
            151.0,
            anchor="nw",
            text="Vendor",
            fill="#000000",
            font=("RobotoRoman Bold", 14 * -1)
        ))

        self.text_ids.append(self.canvas.create_text(
            393.0,
            151.0,
            anchor="nw",
            text="Mac Address",
            fill="#000000",
            font=("RobotoRoman Bold", 14 * -1)
        ))
    
    def hide_elements(self,screen_type='DHCP'):
        if screen_type == 'DHCP' and hasattr(self, 'rectangle_id') and hasattr(self, 'image_1_id'):
            self.canvas.delete(self.rectangle_id)
            self.canvas.delete(self.image_1_id)

        for text_id in self.text_ids:
            self.canvas.delete(text_id)
        self.text_ids = []

    def show(self):
        self.window.resizable(False, False)
        self.window.mainloop()

    def save_event(self):
        sys.exit(0)

    def cancel_event(self):
        sys.exit(0)

if __name__ == "__main__":
    main()
