#!/usr/bin/env python2
# -*- coding: utf-8 -*-

'''This is a small app that converts a character into various representations:
binary, hexademical code points, utf-8/utf-16 code points, decimal'''

import codecs
import re
import sys
import ttk
import unicodedata

from Tkinter import IntVar, Text, Tk, END


class Charconv(ttk.Frame):
    def __init__(self, master):
        '''Instantiating main Frame'''
        ttk.Frame.__init__(self, master)
        self.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)
        self.make_gui()
        self.welcome()
        self.console_debugging()

    def welcome(self):
        '''Displays welcome message'''
        self.Welcome = ttk.Label(self.InfoFrame, font='TkDefaultFont 10',
                                 text=WELCOME, wraplength='350', anchor='nw',
                                 justify='left')
        self.Welcome.grid(column=0, row=0)

    # binding main keys
    def press_return(self, *args):
        '''Processing query when "Enter" gets pressed'''
        char_query = self.Entry.get()
        self.process_query(char_query)

    def select_all(self, *args):
        '''Select all text in the text widget.
        <Overwriting tkinter default 'ctrl + />'''
        # checking which widget has focus
        if self.Entry is self.focus_get():
            self.Entry.select_range(0, 'end')
        return 'break'

    def rebuild_Query(self):
        '''Cleaning up ResultFrame widgets'''
        try:
            self.Welcome.destroy()
            self.NoQuery.destroy()
        except:
            pass

    def process_query(self, query):
        '''Processing entered query'''
        self.REVERSE = False
        self.rebuild_ResultFrame()
        if not query:
            self.rebuild_Query()
            self.NoQuery = ttk.Label(self.ResultFrame,
                                     font='TkDefaultFont 11',
                                     text='Give me a Char/String please!')
            self.NoQuery.grid()
        elif self.reverse_query(query):
            self.rebuild_Query()
            self.ReverseQuery = ttk.Label(self.ResultFrame,
                                          font='TkDefaultFont 11',
                                          text='reverse query')
            self.ReverseQuery.grid()
            self.REVERSE = True
            self.Entry.delete(0, END)
            self.Entry.insert(0, query)
            query = query[:50]  # limiting reverse_query input
            uquery, query_info, restored_cache = self.restore_encoded(query)
            self.result_inserter(uquery, query_info, restored_cache)
        else:
            self.Entry.delete(0, END)
            self.Entry.insert(0, query)
            query = query[:10]  # limit query to 20 chars
            query_info = self.get_info(query)
            result_cache = self.query_dispatcher(query)
            self.result_inserter(query, query_info, result_cache)

    def query_dispatcher(self, query):
        '''Invoking required converting functions'''
        result_cache = []
        check_boxes = (self.isuni, self.isesc, self.isutf8, self.isutf16,
                       self.isdeci, self.isbin)

        switcher = {0: self.continue_fun, 1: self.get_unicode, 2: self.get_esc,
                    3: self.get_utf8, 4: self.get_utf16, 5: self.get_deci,
                    6: self.get_bin}

        for func in check_boxes:
            result_cache.append(switcher[func.get()](query))

        return result_cache

    def continue_fun(self, query):
        '''Return function'''
        return

    def reverse_query(self, query):
        '''Checking if query is an actual representation type'''
        rgxs = (r'0x.+', r'\\x.+')
        if re.match(r'\\u.{3,}', query):
            self.OTHER_REPR = False
            return True
        for rgx in rgxs:
            if re.match(rgx, query):
                self.OTHER_REPR = True
                return True
        return False

    def bad_Query(self):
        '''Displays a message if reverse query is incorrect'''
        try:
            self.BadQuery.destroy()
        except:
            pass
        self.BadQuery = ttk.Label(self.ResultFrame,
                                  font='TkDefaultFont 11 bold',
                                  text='incorrect query!')
        self.BadQuery.grid()

    def restore_encoded(self, query):
        '''Restoring encoded query'''
        qinfo = []
        restored_cache = []
        uquery = u''
        if self.OTHER_REPR:
            try:
                query = query.lstrip('0x|\\x')
                query = unichr(int(query, 16)).encode('utf-8')
                uquery = re.sub('0', r'\\', unicode(query, 'utf-8'))
            except:
                self.bad_Query()
        else:
            try:
                uquery = unicode(query, 'utf-8')
                uquery = uquery.decode('unicode_escape').split()
            except:
                self.bad_Query()

        for q in query.split():
            uq = unicode(q, 'utf-8')
            if not self.OTHER_REPR:
                try:
                    qinfo.append(unicodedata.name(uq.decode('unicode_escape')))
                except:
                    self.bad_Query()
            else:
                try:
                    qinfo.append(unicodedata.name(uq))
                except:
                    self.bad_Query()
            restored_cache.append(query.encode('utf-8'))
        return uquery, qinfo, restored_cache

    def char_cache(self, query):
        '''Caching chars into list'''
        return [c for c in query]

    def get_info(self, query):
        '''Getting unicodedata information on the query'''
        u_query = unicode(query)
        u_query_info = [unicodedata.name(c) for c in u_query]
        return u_query_info

    def get_unicode(self, query):
        '''Converting query to unicode code points'''
        char_cache = self.char_cache(query)
        uni_c = ["U+{:04X}".format(ord(c)) for c in char_cache]
        return uni_c

    def get_esc(self, query):
        '''Converting query to unicode escapes notation'''
        char_cache = self.char_cache(query)
        esc_c = ['\u{:04X}'.format(ord(c)) for c in char_cache]
        return esc_c

    def get_utf8(self, query):
        '''Converting query to utf8 code points'''
        char_cache = self.char_cache(query)
        utf8_c = [c.encode('hex').upper() for c in char_cache]
        return utf8_c

    def get_utf16(self, query):
        '''Converting query to utf16 code points'''
        char_cache = self.char_cache(query)
        utf16_c = [c.encode('utf-16').encode('hex').upper()
                   for c in char_cache]
        return utf16_c

    def get_deci(self, query):
        '''Converting query to decimal notation'''
        char_cache = self.char_cache(query)
        deci_c = [ord(c) for c in char_cache]
        return deci_c

    def get_bin(self, query):
        '''Converting query to binary notation'''
        char_cache = self.char_cache(query)
        bin_c = [''.join(format(ord(c), 'b')) for c in char_cache]
        return bin_c

    def list_unpacker(self, custom_list):
        '''Unpacking lists to strings'''
        list_str = ''
        for item in custom_list:
            list_str = ' '.join([list_str, str(item) + ','])
        return list_str.rstrip(',')

    def text_inserter(self, n, res, query):
        '''Inserting text into result frame'''
        colors = {0: '#ccccff', 1: '#ccffcc', 2: '#ffcccc', 3: '#ff99ff',
                  4: '#ccccff', 5: '#cbcbcb'}
        # setting ResText widget length
        lengths = {}
        try:
            lengths[n] = len(str(res[0])) + 3
        except:
            lengths[n] = 0
        self.ResText = Text(self.ResultFrame, height=1,
                            width=len(query)*lengths[n],
                            font='TkDefaultFont 11', borderwidth=2,
                            # background=root.cget('bg')
                            background=colors[n])
        if isinstance(res, list):
            ures = self.list_unpacker(res)
        elif not self.OTHER_REPR:
            ures = unicode(res, 'utf-8')
            ures = ures.decode('unicode_escape')
        else:
            ures = unicode(res, 'utf-8')
        self.ResText.insert(1.0, ures)
        self.ResText.configure(state='normal', relief='groove')
        self.ResText.grid(sticky='w')

    def result_inserter(self, query, query_info, result_cache):
        '''Inserting results adding colors into Result widget'''
        # inserting char information
        for n in range(len(query_info)):
            full_q = ' '.join(['"' + query[n] + '" -->', query_info[n]])
            self.Info = ttk.Label(self.InfoFrame, font='TkDefaultFont 10',
                                  text=full_q, wraplength='350', anchor='nw',
                                  justify='left')
            self.Info.grid(sticky='w')

        # inserting conversion results,
        '''result_cache is a list where [[get_unicode], [get_esc], [get_utf8],
        [get_utf16], [get_deci], [get_bin]]'''
        for n in range(len(result_cache)):
            if not result_cache[n]:
                self.text_inserter(n, '', query)
                continue
            self.text_inserter(n, result_cache[n], query)

    def make_signs_table(self):
        '''Creating common sign buttons'''
        # button special signs
        signs = {0: u'℃', 1: u'°', 2: u'¹', 3: u'²', 4: u'³', 5: u'′', 6: u'″',
                 7: u'±', 8: u'∓', 9: u'÷', 10: u'≠', 11: u'≡', 12: u'≤',
                 13: u'≥', 14: u'≪', 15: u'≫', 16: u'≃', 17: u'≈', 18: u'√',
                 19: u'∛', 20: u'∜', 21: u'½', 22: u'⅓', 23: u'¼', 24: u'¾',
                 25: u'⅜', 26: u'‰', 27: u'∝', 28: u'≉', 29: u'≅', 30: u'≇',
                 31: u'∣', 32: u'∤', 33: u'£', 34: u'€', 35: u'¥', 36: u'∑',
                 37: u'∏', 38: u'∐', 39: u'∈', 40: u'∉', 41: u'∋', 42: u'∌',
                 43: u'∅', 44: u'∞', 45: u'∧', 46: u'∨', 47: u'∩', 48: u'∪',
                 49: u'⊂', 50: u'⊃', 51: u'⊄', 52: u'⊅', 53: u'⊆', 54: u'⊇',
                 55: u'⊈', 56: u'⊉', 57: u'¶', 58: u'·', 59: u'∘', 60: u'◊',
                 61: u'¤', 62: u'§', 63: u'π', 64: u'ƒ', 65: u'Δ', 66: u'µ',
                 67: u'α', 68: u'ß', 69: u'γ', 70: u'Å', 71: u'´', 72: u'´',
                 73: u'¯', 74: u'№', 75: u'©', 76: u'®', 77: u'™', 78: u'℠'}

        # columns range
        vbox = {0: 0,
                1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 0,
                10: 1, 11: 2, 12: 3, 13: 4, 14: 5, 15: 6, 16: 7, 17: 8, 18: 0,
                19: 1, 20: 2, 21: 3, 22: 4, 23: 5, 24: 6, 25: 7, 26: 8, 27: 0,
                28: 1, 29: 2, 30: 3, 31: 4, 32: 5, 33: 6, 34: 7, 35: 8, 36: 0,
                37: 1, 38: 2, 39: 3, 40: 4, 41: 5, 42: 6, 43: 7, 44: 8, 45: 0,
                46: 1, 47: 2, 48: 3, 49: 4, 50: 5, 51: 6, 52: 7, 53: 8, 54: 0,
                55: 1, 56: 2, 57: 3, 58: 4, 59: 5, 60: 6, 61: 7, 62: 8, 63: 0,
                64: 1, 65: 2, 66: 3, 67: 4, 68: 5, 69: 6, 70: 7, 71: 8, 72: 0,
                73: 1, 74: 2, 75: 3, 76: 4, 77: 5, 78: 6}

        # rows range
        hbox = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0,
                9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1,
                18: 2, 19: 2, 20: 2, 21: 2, 22: 2, 23: 2, 24: 2, 25: 2, 26: 2,
                27: 3, 28: 3, 29: 3, 30: 3, 31: 3, 32: 3, 33: 3, 34: 3, 35: 3,
                36: 4, 37: 4, 38: 4, 39: 4, 40: 4, 41: 4, 42: 4, 43: 4, 44: 4,
                45: 5, 46: 5, 47: 5, 48: 5, 49: 5, 50: 5, 51: 5, 52: 5, 53: 5,
                54: 6, 55: 6, 56: 6, 57: 6, 58: 6, 59: 6, 60: 6, 61: 6, 62: 6,
                63: 7, 64: 7, 65: 7, 66: 7, 67: 7, 68: 7, 69: 7, 70: 7, 71: 7,
                72: 8, 73: 8, 74: 8, 75: 8, 76: 8, 77: 8, 78: 8}

        for n in signs:
            ttk.Button(self.SignsFrame, width='2', padding=(1, 1),
                       text=signs[n], command=lambda sign = signs[n]:
                       self.process_query(sign)).grid(column=vbox[n],
                                                      row=hbox[n])

    def make_gui(self):
        '''Creating main app interface'''
        expand = dict(sticky='nsew', pady=1, padx=1)
        self.MainFrame = ttk.Frame(self, borderwidth='2', relief='groove')
        self.MainFrame.grid(columnspan=2, rowspan=3, **expand)
        self.MainFrame.grid_columnconfigure(0, weight=3)
        self.MainFrame.grid_columnconfigure(1, weight=1, minsize=205)
        self.MainFrame.grid_rowconfigure(0, weight=1)
        self.MainFrame.grid_rowconfigure(1, weight=50)
        self.MainFrame.grid_rowconfigure(2, weight=1)

        # EntryFrame is a container for Entry widget
        self.EntryFrame = ttk.Frame(self.MainFrame, borderwidth='2',
                                    relief='groove')
        self.EntryFrame.grid(column=0, row=0, columnspan=1, rowspan=1,
                             sticky='wne')
        self.EntryFrame.grid_columnconfigure(0, weight=1)
        self.EntryFrame.grid_rowconfigure(0, weight=1)

        # creating Entry widget inside EntryFrame container
        self.Entry = ttk.Entry(self.EntryFrame, font='Tahoma 21')
        self.Entry.grid(column=0, row=0, columnspan=1, **expand)
        # binding keys
        self.Entry.bind('<Control-a>', self.select_all)
        self.Entry.bind('<Return>', self.press_return, '+')
        # <Return> works only when entry is focused
        self.Entry.focus()

        # Process button container
        self.ProcessFrame = ttk.Frame(self.MainFrame, borderwidth='2',
                                      relief='groove')
        self.ProcessFrame.grid_columnconfigure(0, weight=1)
        self.ProcessFrame.grid_rowconfigure(0, weight=1)
        self.ProcessFrame.grid(column=1, row=0, **expand)

        # creating Process button
        self.Process = ttk.Button(self.ProcessFrame, padding=(0, 7),
                                  text='Convert', command=self.press_return)
        self.Process.grid(column=0, row=0, sticky='we')

        # Check-box container
        self.CheckFrame = ttk.Frame(self.MainFrame, borderwidth='2',
                                    relief='groove')
        self.CheckFrame.grid_columnconfigure(0, weight=1)
        self.CheckFrame.grid(column=1, row=2, **expand)

        # creating Check-boxes
        self.isuni = IntVar()
        self.CheckUni = ttk.Checkbutton(self.CheckFrame,
                                        text='Unicode (code point)',
                                        onvalue=1, offvalue=0,
                                        variable=self.isuni)
        self.CheckUni.grid(**expand)
        self.CheckUni.invoke()

        self.isesc = IntVar()
        self.CheckEsc = ttk.Checkbutton(self.CheckFrame,
                                        text='Unicode (escaped hex)',
                                        onvalue=2, offvalue=0,
                                        variable=self.isesc)
        self.CheckEsc.grid(**expand)
        self.CheckEsc.invoke()

        self.isutf8 = IntVar()
        self.CheckUTF8 = ttk.Checkbutton(self.CheckFrame, text='UTF-8 (hex)',
                                         onvalue=3, offvalue=0,
                                         variable=self.isutf8)
        self.CheckUTF8.grid(**expand)
        self.CheckUTF8.invoke()

        self.isutf16 = IntVar()
        self.CheckUTF16 = ttk.Checkbutton(self.CheckFrame, text='UTF-16 (hex)',
                                          onvalue=4, offvalue=0,
                                          variable=self.isutf16)
        self.CheckUTF16.grid(**expand)
        self.CheckUTF16.invoke()

        self.isdeci = IntVar()
        self.CheckDeci = ttk.Checkbutton(self.CheckFrame, text='Decimal',
                                         onvalue=5, offvalue=0,
                                         variable=self.isdeci)
        self.CheckDeci.grid(**expand)
        self.CheckDeci.invoke()

        self.isbin = IntVar()
        self.CheckBin = ttk.Checkbutton(self.CheckFrame, text='Binary',
                                        onvalue=6, offvalue=0,
                                        variable=self.isbin)
        self.CheckBin.grid(**expand)
        self.CheckBin.invoke()

        # Sings button container
        self.SignsFrame = ttk.Frame(self.MainFrame, borderwidth='2',
                                    relief='groove')
        self.SignsFrame.grid(column=1, row=1, **expand)

        # creating Common signs buttons
        self.make_signs_table()

        # Results container
        self.rebuild_ResultFrame()

    def rebuild_ResultFrame(self):
        '''Refreshing results frame'''
        try:
            self.ResultFrame.destroy()
            self.InfoFrame.destroy()
        except:
            pass

        # Characters info frame
        self.InfoFrame = ttk.Frame(self.MainFrame, borderwidth='2',
                                   relief='groove')
        self.InfoFrame.grid(column=0, row=1, sticky='wnse')

        # Convertion results frame
        self.ResultFrame = ttk.Frame(self.MainFrame, borderwidth='2',
                                     relief='groove')
        self.ResultFrame.grid_columnconfigure(0, weight=1)
        self.ResultFrame.grid(column=0, row=2, sticky='wnse')

    def console_debugging(self):
        '''Setting utf-8 env for correct cmd output while debugging'''
        reload(sys)
        sys.setdefaultencoding('utf-8')
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
        sys.stderr = codecs.getwriter('utf8')(sys.stderr)

# Welcome message
WELCOME = '''Charconv 0.1 is a small app that displays input query in \
various unicode representation formats.

Choose your format type on the lower right pane.
Enter a string (10 chars max) in the query above \
and press "Convert" button to see the results.

You can do a reverse query in \\u, 0x, \\x notation as well.'''


# starting main interface loop
if __name__ == "__main__":
    root = Tk()
    root.title('Charconv 0.1')
    root.geometry("570x430")  # geometry size when the app is started
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    root.resizable(True, True)
    root.update()

    # you can use ttk themes here ('clam', 'alt', 'classic', 'default')
    # ttk_theme = ttk.Style()
    # ttk_theme.theme_use('clam')

    app = Charconv(root)
    app.mainloop()

# TODO
