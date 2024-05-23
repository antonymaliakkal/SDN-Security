import tkinter as tk
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.log import setLogLevel
from mininet.cli import CLI
import time
from PIL import Image, ImageTk
from tkinter import ttk
from gui.attack import Attack
from pydub import AudioSegment
from pydub.playback import play

window = None
prevState = None
alertTimer = None
musicPlayed = False

class CustomTopology(Topo):
    def build(self):
        # Add switch
        switch = self.addSwitch('s1')

        # Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        malicious1 = self.addHost('m1')

        # Connect hosts to switch
        self.addLink(host1, switch)
        self.addLink(host2, switch)
        self.addLink(malicious1, switch)

class NetworkGUI:
    def __init__(self, master, net):
        self.master = master
        self.net = net
        self.master.title("Mininet GUI")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', foreground='white', background='#424242', bordercolor='#0066b2', lightcolor='#212121', darkcolor='#212121')
        self.style.configure("TFrame", bordercolor="#0066b2")

        self.canvas = tk.Canvas(self.master, width=800, height=600)
        self.canvas.grid(row=0, column=0, columnspan=2)
        self.alert_label = tk.Label(self.master, text="", font=("Arial", 20), fg="red")


        # Dictionary to store host positions
        self.host_positions = {}
        
        hosts = [host.name for host in self.net.hosts]
        self.host_images = {}
        
        self.button_frame = ttk.Labelframe(self.master, text='My widgets')
        self.button_frame.grid(row=1, column=0, padx=10, pady=10)
        
        self.attack_frame = ttk.Labelframe(self.master, text='Attacks')
        self.attack_frame.grid(row=1, column=1, padx=10, pady=10)
        
        
        # Dropdown menu for selecting source host
        self.source_var = tk.StringVar(master)
        self.source_var.set(hosts[0])  # Default value
        self.source_dropdown = ttk.OptionMenu(self.button_frame, self.source_var, *hosts)
        self.source_dropdown.grid(row=0, column=0, padx=5)

        # Dropdown menu for selecting destination host
        self.dest_var = tk.StringVar(master)
        self.dest_var.set(hosts[1])  # Default value
        self.dest_dropdown = ttk.OptionMenu(self.button_frame, self.dest_var, *hosts)
        self.dest_dropdown.grid(row=0, column=1, padx=5)

        # Add Send Packet button at the bottom
             
        self.send_packet_button = ttk.Button(self.button_frame, text="Send Packet", command=self.send_packet)
        self.send_packet_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10)
        
        self.attack = Attack()
        self.send_packet_button = ttk.Button(self.attack_frame, text="Initiate DoS", command=lambda:self.attack.DoS(self.net, 'm1'))
        self.send_packet_button.grid(row=1, column=1, padx=10, pady=10)
                    
                    
        #self.send_packet_button = ttk.Button(self.attack_frame, text="Initiate U2R", command=self.send_packet)
        #self.send_packet_button.grid(row=1, column=2, padx=10, pady=10)
                    
        #self.send_packet_button = ttk.Button(self.attack_frame, text="Initiate R2L", command=self.send_packet)
        #self.send_packet_button.grid(row=1, column=3, padx=10, pady=10)
                    
        self.send_packet_button = ttk.Button(self.attack_frame, text="Initiate DNS Probe", command=self.send_packet)
        self.send_packet_button.grid(row=1, column=4, padx=10, pady=10)

        # Update GUI with initial network state
        self.update_network_state()

    def update_network_state(self):
        # Clear previous host positions
        self.host_positions = {}
        img_size = 80 
        padding = 100

        # Clear canvas
        self.canvas.delete("all")


        # Get host positions
        hosts = self.net.hosts
        num_hosts = len(hosts)
        

        for i, host in enumerate(hosts):
            x = padding + i * 150
            y = padding
            self.host_positions[host] = (x, y)
            
            # Draw link between host and controller
            controller_x, controller_y = 390 - img_size / 2 + padding, 290 - img_size / 2 + padding
            self.canvas.create_line(x, y, controller_x, controller_y, dash=(8, 8), width=3, fill="#0066b2")
            
            # Draw host node
            if host.name[0] == 'm':
                image_path = 'gui/virus.png'  # Replace with your malicious host image path
            else:
                image_path = 'gui/host.png'
            image = Image.open(image_path)
            image = image.resize((img_size, img_size), Image.LANCZOS)  # Adjust size if needed
            host_image = ImageTk.PhotoImage(image)
            self.host_images[host] = host_image  # Retain reference to the ima
            #self.canvas.create_oval(x - 10, y - 10, x + 10, y + 10, fill=color, outline="black")
            self.canvas.create_image(x, y, anchor=tk.CENTER, image=host_image)
            self.canvas.create_text(x, y + 20, text=host.name)

        
        # Draw controller node
        cimage = Image.open('gui/controller.png')
        cimage = cimage.resize((img_size, img_size), Image.LANCZOS)  # Adjust size if needed
        controller_image = ImageTk.PhotoImage(cimage)
        self.host_images['controller'] = controller_image
        self.canvas.create_image(390 - img_size / 2 + padding, 290 - img_size / 2 + padding, anchor=tk.CENTER, image=controller_image)
        self.canvas.create_text(400, 300, text="Controller")
        
        # Update GUI
        self.canvas.update()
        
    def animate_packet(self, source, destination):
        # Get coordinates of source and destination
        source_x, source_y = self.host_positions[source]
        dest_x, dest_y = self.host_positions[destination]
        controller_x, controller_y = 400, 300
        
        color = 'green'
        if source.name[0] == 'm':
            color='red'

        # Animate packet from source to controller
        for i in range(20):
            self.canvas.delete("packet")
            x = source_x + (controller_x - source_x) * i / 20
            y = source_y + (controller_y - source_y) * i / 20
            self.canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, outline="")
            self.canvas.tag_lower("packet")
            self.canvas.update()
            time.sleep(0.05)
            
        if source.name[0] == 'm':
            self.display_alert("Malicious packet received!")
        else:

        # Animate packet from controller to destination
            for i in range(20):
                self.canvas.delete("packet")
                x = controller_x + (dest_x - controller_x) * i / 20
                y = controller_y + (dest_y - controller_y) * i / 20
                self.canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, outline="")
                self.canvas.tag_lower("packet")
                self.canvas.update()
                time.sleep(0.05)
            
            
    def send_packet(self):
        # Simulate sending packet from h1 to h2
        source_host = self.source_var.get()
        dest_host = self.dest_var.get()
        #self.net.ping([source_host, dest_host])
        self.net.ping([self.net.get(source_host), self.net.get(dest_host)])
        self.animate_packet(self.net.get(source_host), self.net.get(dest_host))
        # Update network state after packet is sent
        self.update_network_state()

    # def sendTcp(self):


    def display_alert(self, message):
        # Display alert message in a pop-up window at the center of the screen
        self.alert_label.config(text=message)
        self.alert_label.place(relx=0.5, rely=0.5, anchor="center")
        self.master.after(2000, self.hide_alert)

    def hide_alert(self):
        # Hide the alert message after 2 seconds
        self.alert_label.config(text="")
        self.alert_label.place_forget()

def hide_alert(label_inst):
    # Hide the alert message after 2 seconds
    global musicPlayed
    label_inst.config(text="")
    label_inst.place_forget()
    musicPlayed = False

def displayAlert(resObj):
    global prevState, alertTimer, musicPlayed
    print(resObj)
    if(alertTimer):
        window.after_cancel(alertTimer)
    if(window):
        label_inst = tk.Label(window, text="", font=("Arial", 20), fg="red")
        label_inst.config(text="Malicious packet detected")
        label_inst.place(relx=0.5, rely=0.5, anchor="center")
        alertTimer = window.after(3000,lambda:hide_alert(label_inst))
        if not musicPlayed:
            sound = AudioSegment.from_file("gui/siren.mp3")
            play(sound)
            musicPlayed = True
            
        # prevState = resObj['status']

def main():
    # setLogLevel('info')
    global window

    topo = CustomTopology()
    controller = RemoteController('c0', port=6633, ip='127.0.0.1')
    net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, build=False, autoSetMacs=True)
    # controller = CustomController(topo)
    net.start()
    net.get('s1').cmd('ovs-ofctl add-flow s1 priority=1,actions=controller')
    # CLI(net)
    root = tk.Tk()
    window = root
    app = NetworkGUI(root, net)
    #for i in range(10):
    #  app.send_packet('h1','h2')
    root.mainloop()

    net.stop()

# if __name__ == "__main__":
#     main()