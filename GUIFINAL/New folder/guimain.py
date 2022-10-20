import tkinter as tk
import plotly_graphs as pg
from tkinter import ttk, filedialog
import pandas as pd
from tkinter import *
from PIL import Image, ImageTk
from tkinter import messagebox

master = tk.Tk()
master.geometry('1455x500')
master.title('A Comprehensive List of Latest CVE Vulnerabilities Abused by Ransomware Gangs ')
master.resizable(False, False)
style = ttk.Style()
style.theme_names()

# ---------------------DISPLAY TABS FUNCTIONS---------------------------------------------------------------------------
my_notebook = ttk.Notebook(master)
my_notebook.grid(pady=0)
my_frame1 = Frame(my_notebook, width=1455, height=800)
my_frame2 = Frame(my_notebook, width=1455, height=800)
my_frame1.pack(fill='both', expand=1)
my_frame1.pack(fill='both', expand=1)
my_notebook.add(my_frame1, text='Graph Tab')
my_notebook.add(my_frame2, text='Table Tab')


# ---------------------DISPLAY GRAPH FUNCTIONS-------------------------------------------------------------------------


# cve_per_year graph from plotly_graphs
def interact_cve_per_year():
    pg.cve_per_year(1)


def static_cve_per_year():
    pg.cve_per_year(2)
    configure_image('cve_per_year.png')
    interactive_button(interact_cve_per_year)


# severity graph from plotly_graphs
def interact_severity():
    pg.severity(1)


def static_severity():
    pg.severity(2)
    configure_image('severity.png')
    interactive_button(interact_severity)


# popular_cve_per_year graph from plotly_graphs
def interact_popular_cve_per_year():
    pg.popular_cve_per_year(1)


def static_popular_cve_per_year():
    pg.popular_cve_per_year(2)
    configure_image('popular_cve_per_year.png')
    interactive_button(interact_popular_cve_per_year)


# top_ten_cve graph from plotly_graphs
def interact_top_ten_cve():
    pg.top_ten_cve(1)


def static_top_ten_cve():
    pg.top_ten_cve(2)
    configure_image('top_ten_cve.png')
    interactive_button(interact_top_ten_cve)


# most_active_groups graph from plotly_graphs
def interact_most_active_groups():
    pg.most_active_groups(1)


def static_most_active_groups():
    pg.most_active_groups(2)
    configure_image('most_active_groups.png')
    interactive_button(interact_most_active_groups)


# popular_group_cwe graph from plotly_graphs
def interact_popular_group_cwe():
    pg.popular_group_cwe(1)


def static_popular_group_cwe():
    pg.popular_group_cwe(2)
    configure_image('popular_group_cwe.png')
    interactive_button(interact_popular_group_cwe)


# groups_victim_count graph from plotly_graphs
def interact_groups_victim_count():
    pg.groups_victim_count(1)


def static_groups_victim_count():
    pg.groups_victim_count(2)
    configure_image('groups_victim_count.png')
    interactive_button(interact_groups_victim_count)


def interact_vectors_avg_severity():
    pg.vectors_avg_severity(1)


def static_vectors_avg_severity():
    pg.vectors_avg_severity(2)
    configure_image('vectors_avg_severity.png')
    interactive_button(interact_vectors_avg_severity)


def configure_image(png):
    image = Image.open(png)
    resize_image = image.resize((500, 400))
    image = ImageTk.PhotoImage(resize_image)

    static_graph.configure(image=image)
    static_graph.image = image


def interactive_button(graph):
    button_0 = tk.Button(my_frame1,
                         width=20,
                         text='See interactive graph',
                         command=graph)
    button_0.place(x=30, y=385)
    graph_label = tk.Label(my_frame1,
                           text='Quick View Graphs',
                           font=('Roboto Medium', -16))  # font name and size in px
    graph_label.place(x=420, y=5)


# -----------------------------------WIDGETS ---------------------------------------------------------------------------

# Labelframe
file_frame = tk.LabelFrame(my_frame1)
file_frame.place(height=365, width=200, rely=0.01, relx=0, x=10)

# Labels
button_label = tk.Label(my_frame1,
                        text='Graphs',
                        font=('Roboto Medium', -16))  # font name and size in px
button_label.place(x=75, y=20)

static_graph = tk.Label(my_frame1)
static_graph.place(x=250, y=30)

# Buttons
button_1 = tk.Button(my_frame1,
                     width=20,
                     text='Total CVEs per year',
                     command=static_cve_per_year)
button_1.place(x=30, y=50)

button_2 = tk.Button(my_frame1,
                     width=20,
                     text='Severity per year',
                     command=static_severity)
button_2.place(x=30, y=90)

button_3 = tk.Button(my_frame1,
                     width=20,
                     text='Popular CVEs per year',
                     command=static_popular_cve_per_year)
button_3.place(x=30, y=130)

button_4 = tk.Button(my_frame1,
                     width=20,
                     text='Top 10 Popular CVEs',
                     command=static_top_ten_cve)
button_4.place(x=30, y=170)

button_5 = tk.Button(my_frame1,
                     width=20,
                     text='Most Active Groups',
                     command=static_most_active_groups)
button_5.place(x=30, y=210)

button_6 = tk.Button(my_frame1,
                     width=20,
                     text='Popular CWE in Groups',
                     command=static_popular_group_cwe)
button_6.place(x=30, y=250)

button_7 = tk.Button(my_frame1,
                     width=20,
                     text='Victim Count per Groups',
                     command=static_groups_victim_count)
button_7.place(x=30, y=290)

button_8 = tk.Button(my_frame1,
                     width=20,
                     text='Severity in Attack Vectors',
                     command=static_vectors_avg_severity)
button_8.place(x=30, y=330)

# ---------------------DISPLAY TABLE FUNCTIONS--------------------------------------------------------------------------
# Frame for open file dialog
file_frame = tk.LabelFrame(my_frame2, text='Open File')
file_frame.place(height=100, width=900, rely=0.45, relx=0, x=270)

# Buttons
button1 = tk.Button(file_frame, text='Browse A File', command=lambda: File_dialog())
button1.place(rely=0.65, relx=0.30)

button2 = tk.Button(file_frame, text='Load File', command=lambda: Load_excel_data())
button2.place(rely=0.65, relx=0.50)

# The file/file path text
label_file = ttk.Label(file_frame, text='No File Selected')
label_file.place(rely=0, relx=0)

my_frame2 = Frame(my_frame2)
my_frame2.grid(pady=0)
filename = None


def File_dialog():
    global df
    global filename
    filename = filedialog.askopenfilename(initialdir='/',
                                          title='Select A File')
    label_file['text'] = filename
    return None


def Load_excel_data():
    file_path = label_file['text']
    try:
        excel_filename = r'{}'.format(file_path)
        if excel_filename[-4:] == '.csv':
            df = pd.read_csv(excel_filename)
        else:
            df = pd.read_excel(excel_filename)

    except ValueError:
        tk.messagebox.showerror('Information', 'The file you have chosen is invalid')
        return None
    except FileNotFoundError:
        tk.messagebox.showerror('Information', f'No such file as {file_path}')
        return None

    def create_column_combox():
        def populate_values_combo(e=None):
            state = 'normal'
            combo_values = []
            if col_combo.get() == 'All':
                state = 'disabled'
                select_value()
            else:
                combo_values = ['All'] + df[col_combo.get()].unique().tolist()

            col_values_combo.config(values=combo_values, state=state)

        def select_value(e=None):
            tree.delete(*tree.get_children())
            if col_combo.get() == 'All' or col_values_combo.get() == 'All':
                col_values_combo.current(0)  # setting values to All
                [tree.insert('', 'end', text=str(index), values=list(row)) for index, row in df.iterrows()]
            else:
                for index, row in df.loc[df[col_combo.get()].eq(col_values_combo.get())].iterrows():
                    tree.insert('', 'end', text=index, values=list(row))

        columns = ['All', 'CVE', 'Group Name', 'Severity', 'Attack Vector', 'Attack Complexity',
                   'Privileges Required']  # Adding option All to list of columns
        column_combo_label = Label(my_frame2, text='Category')
        column_combo_label.pack()
        col_combo = ttk.Combobox(my_frame2, values=columns, state='readonly')
        col_combo.pack()
        col_combo.bind('<<ComboboxSelected>>', populate_values_combo)

        volume_combo_label = Label(my_frame2, text='Values')
        volume_combo_label.pack()
        col_values_combo = ttk.Combobox(my_frame2, state='enabled')
        col_values_combo.pack()
        col_values_combo.bind('<KeyRelease>', select_value)

    create_column_combox()
    clear_treeview()

    tree['column'] = list(df.columns)
    tree['show'] = 'headings'

    for col in tree['column']:
        tree.heading(col, text=col)
        tree.column('#1', anchor='center', width=200)
        tree.column('#2', anchor='center', width=150)
        tree.column('#3', anchor='center', width=150)
        tree.column('#4', anchor='center', width=150)

    df_rows = df.to_numpy().tolist()
    for row in df_rows:
        tree.insert('', 'end', values=row)

    tree.pack()


def clear_treeview():
    tree.delete(*tree.get_children())


tree = ttk.Treeview(my_frame2)

master.mainloop()
