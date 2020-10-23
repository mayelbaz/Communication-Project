import PySimpleGUI as gui
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import time
import sys
from os import system, name
import threading
import Our_collector
import numpy as np=

# ADD TO COLLECTOR A FUNCTION CALLED CLEANUP WHICH CLEANS ALL DATA WITH.
# THIS IS THE NON-EFFECIENT WAY TO COLLECT THE DATA.
invalid = 0xffffff
nsec_to_sec = 1000000000

# ANIMATION RE-DRAW TIME IN MILLESECONDS.
draw_interval = 1000

# LIST CLEANING VARIABLES IN SECONDS
clean_freq = 1
clean_interval = 10


################# DATA EXTRACTION FUNCTIONS #################


def extractEgressBuffer():
    x = []
    y = []
    Our_collector.list_lock.acquire()
    for p in Our_collector.packets:
        if p.is_egress() and int(p.egress_occupancy) != invalid:
            time_stamp = float(p.time_sec) + p.time_nanosec / nsec_to_sec
            if len(x) == 0 or time_stamp != x[-1]:
                x.append(time_stamp)
                y.append(int(p.egress_occupancy))
    Our_collector.list_lock.release()
    return x, y

def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def unique(list1):
    x = np.array(list1)
    return (np.unique(x))



################# MAIN INTERFACE FUNCTIONS #################


def genGraph(name):
    fig = plt.figure(figsize=(7, 6))
    if name == 'user path':
        print("This is the user's path")
    elif name == 'congestion':
        print("This is the congestion")

    # elif name == 'buffersLegacy':
    #       global buffer_animation
    #       fig.suptitle('Buffer Occupancy (real-time)', fontsize=16)
    #       fig.subplots_adjust(hspace = 0.4)
    #       combined_axis = fig.add_subplot(2,1,2)
    #       ingress_axis = fig.add_subplot(2,2,1)
    #       egress_axis = fig.add_subplot(2,2,2)
    #       buffer_animation = animation.FuncAnimation(fig, animateBuffersLegacy, fargs=[combined_axis, ingress_axis, egress_axis], interval=draw_interval)
    else:
        print(name, "is not a legal graph in this GUI.")
        return
    plt.legend()
    plt.show()


def genMainInterface():
    gui.change_look_and_feel('LightGrey5')
    button_font = 'any 14'
    button_border_width = 8
    space_value = 20

    welcome_msg = gui.Text('Welcome to Mellanox Smart Debugger.\n       What would you like to do?', font='any 30',
                           border_width=40)
    leave_btn = gui.Exit(size=(5, 1), font=button_font)
    user_path = gui.Button('Show user’s path', key='user path', size=(16, 4), font=button_font,
                           border_width=button_border_width)
    congestion = gui.Button('Analyze congestion', key='congestion', size=(16, 4), font=button_font,
                            border_width=button_border_width)
    outputy = gui.Output(size=(105, 20))
    logs = gui.Button('Export logs', key= 'Export logs', size = (16,4), font=button_font, border_width=button_border_width)	
    Seperate = gui.Button('Seperate flows', key='Seperate flows', size = (16,4), font= button_font, border_width=button_border_width)

    layout = [
        [gui.T(' ' * 14 * space_value),                                                       leave_btn],
        [    welcome_msg],
        [gui.T(' ' * 5), user_path,  congestion,  logs,  Seperate,   ],
        [gui.T(' ' * space_value), outputy  ],
        [gui.T(' ' * button_border_width)]
    ]
    interface = gui.Window('Collector Interface', layout, finalize=True)
    return interface



def stringy(obj):
    if obj is None:
        return ""
    return str(obj)


# MAIN
GUI = genMainInterface()
# Turn on interactive mode for multiple windows
plt.ion()
# Collector Initialization
sniffer_thread = threading.Thread(target=Our_collector.sniff_packets, args=[])
maintain_list_thread = threading.Thread(target=Our_collector.maintain_list, args=[clean_freq, clean_interval])
sniffer_thread.start()
maintain_list_thread.start()
keep_going = True

# Await input
while keep_going:
    print("Waiting for input...")
    event, values = GUI.read()
    if event in (None, 'Exit'):
        GUI.close()
        Our_collector.stop_threads = True
        Our_collector.stopShell()
        sniffer_thread.join()
        maintain_list_thread.join()
        keep_going = False
        break
    elif event == 'user path':
        print("Showing user’s path")
        Our_collector.showUser()
    elif event == 'congestion':
        print("Analyzing congestion")
        Our_collector.analyzeCongestion()
    elif event == 'Export logs':
        print("Exporting logs to logs.txt file")
        orig_std = sys.stdout
        logs_file = open("logs.txt","a")
        sys.stdout = logs_file
        logs_file.write("information according to time: ")
        logs_file.write(str(time.asctime( time.localtime(time.time()) )) + "\n\n")
        logs_file.write(stringy(Our_collector.showUser()) + "\n")
        logs_file.write(stringy(Our_collector.extractFlowInformation()))
        sys.stdout = orig_std
    elif event == 'Seperate flows':
        print("Seperating the flows")
        Our_collector.extractFlowInformation()

print("Closing GUI...")
GUI.close()
print("Finished!")
