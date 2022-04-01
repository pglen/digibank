#!/usr/bin/env python

import os, sys, getopt, signal
import gobject, gtk, pango

import random, time
import treehand, sutil, padding

class NewCust(gtk.Window):
    
    def __init__(self, par, cback, uuid_name, datax = None):
    
        self.cback = cback
        self.ok = False
        self.arr = []
        gtk.Window.__init__(self)
        self.set_transient_for(par)
        self.set_modal(True)
        
        if datax  == None:
            self.set_title("Create new DIBA customer.")
        else:
            self.set_title("Edit DIBA customer.")
            
        self.set_position(gtk.WIN_POS_CENTER)
        
        #ic = gtk.Image(); ic.set_from_stock(gtk.STOCK_DIALOG_INFO, gtk.ICON_SIZE_BUTTON)
        #window.set_icon(ic.get_pixbuf())
        #www = gtk.gdk.screen_width(); hhh = gtk.gdk.screen_height();
        
        www, hhh = sutil.get_screen_wh()
        
        self.set_default_size(3*www/4, 3*hhh/4)
        
        self.set_flags(gtk.CAN_FOCUS | gtk.SENSITIVE)
         
        self.set_events(  gtk.gdk.POINTER_MOTION_MASK |
                            gtk.gdk.POINTER_MOTION_HINT_MASK |
                            gtk.gdk.BUTTON_PRESS_MASK |
                            gtk.gdk.BUTTON_RELEASE_MASK |
                            gtk.gdk.KEY_PRESS_MASK |
                            gtk.gdk.KEY_RELEASE_MASK |
                            gtk.gdk.FOCUS_CHANGE_MASK )
         
        self.connect("key-press-event", self.key_press_event)        
        self.connect("button-press-event", self.area_button)        
        
        try:
            self.set_icon_from_file("icon.png")
        except:
            pass 

        self.arr.append(("custid", str(uuid_name)))
        
        # We use gobj instead of SIGALRM, so it is more multi platform
        #gobject.timeout_add(1000, self.handler_tick)
        
        vbox = gtk.VBox()
        vbox2 = gtk.VBox();
      
        sg = gtk.SizeGroup(gtk.SIZE_GROUP_HORIZONTAL)
          
        tp1 =("Full Name: ", "cname", "Enter full name (TAB to advance)", None)
        tp2 = ("Date of birth: ", "dob", "Date of birth, YYYY/MM/DD", None) 
        lab1, lab2 = self.entryquad(vbox2, tp1, tp2)
        sg.add_widget(lab1);     sg.add_widget(lab2)
        
        tp3 = ("Location of birth: ", "lob", "Location, City and Country", None) 
        tp4 = ("Numeric ID: ", "numid", "Social Security Number or national ID", None) 
        lab3, lab4 = self.entryquad(vbox2, tp3, tp4)
        sg.add_widget(lab3);     sg.add_widget(lab4)
        
        tp3a = ("Address Line 1: ", "addr1", "Address line one. (Number, Street)", None) 
        tp4a = ("Address Line 2: ", "addr2", "Addressline two. (if applicable)", None) 
        lab5, lab6 = self.entryquad(vbox2, tp3a, tp4a)
        sg.add_widget(lab5);     sg.add_widget(lab6)
        
        tp5 = ("City: ", "city", "City or Township", None) 
        tp6 = ("County / Territory: ", "county", "County or Teritory or Borough", None) 
        lab7, lab8 = self.entryquad(vbox2, tp5, tp6)
        sg.add_widget(lab7);     sg.add_widget(lab8)
        
        tp7 = ("Zip: ", "zip", "Zip code or Postal code", None) 
        tp8 = ("Country: ", "country", "Coutry of residence", None) 
        lab9, lab10 = self.entryquad(vbox2, tp7, tp8)
        sg.add_widget(lab9);     sg.add_widget(lab10)
        
        tp7a = ("Phone: ", "phone", "Phone or text number. ", None) 
        tp8a = ("Email: ", "email", "Primary Email", None) 
        lab9a, lab10a = self.entryquad(vbox2, tp7a, tp8a)
        sg.add_widget(lab9a);     sg.add_widget(lab10a)
        
        tp7b = ("Phone: (secondary)", "phone2", "Secondary phone or text number. ", None) 
        tp8b = ("Email: (Secondary)", "email2", "Secondary Email", None) 
        lab9b, lab10b = self.entryquad(vbox2, tp7b, tp8b)
        sg.add_widget(lab9b);     sg.add_widget(lab10b)
        
        self.vspacer(vbox)
        vbox.pack_start(vbox2, False)
        
        vbox3 = gtk.VBox();
        
        lab1a = self.textviewpair(vbox3, "Comments: ", "comments", \
                "Enter comments. This field could contain additiona data. "
                "   (Ctrl-TAB to advance)")
        sg.add_widget(lab1a)
        
        lab5 = self.textviewpair(vbox3, "Free Text: ", "freetext", \
                "Enter free flowing text, relevant to the entry.")
        sg.add_widget(lab5)
        
        lab2a = self.textviewpair(vbox3, "Log entry:", "log", \
                "Enter log entry. (Append at end, keep old entries.)")
        sg.add_widget(lab2a)
        
        vbox.pack_start(vbox3, False)
        self.vspacer(vbox, expand = True)
        
        # Draw buttons
        hbox = gtk.HBox()
        
        #lab00 = gtk.Label("        ")
        #hbox.pack_start(lab00, False)
        
        lab0 = gtk.Label("               " \
                "Customer ID:  '" + str(uuid_name) + "'")
        hbox.pack_start(lab0, False)
        
        lableft = gtk.Label("     ")
        hbox.pack_start(lableft, True)
        
        lab1 = gtk.Label("Alt-X or ESC or Alt-C to Exit, Alt-O to OK, TAB or Ctrl-TAB to advance")
        hbox.pack_start(lab1, False)
        
        lab2 = gtk.Label("     ")
        hbox.pack_start(lab2, False)
        
        butt1 = gtk.Button("     _OK      ")
        butt1.connect("clicked", self.click_ok, self)
        hbox.pack_start(butt1, False)
        self.spacer(hbox)
        
        butt2 = gtk.Button("    _Cancel    ")
        butt2.connect("clicked", self.click_can, self)
        hbox.pack_start(butt2, False)
        self.spacer(hbox)
        
        self.vspacer(vbox)
        vbox.pack_start(hbox, False) 
        self.vspacer(vbox)
        self.add(vbox)
        
    # Run as modal dialog until destroyed
    def run(self):
        self.show_all()
        while True:
            ev = gtk.gdk.event_peek()
            #print ev
            if ev:
                if ev.type == gtk.gdk.DELETE:
                    break
                if ev.type == gtk.gdk.UNMAP:
                    break
            gtk.main_iteration_do()
            
        return self.ok
        
    # --------------------------------------------------------------------
    
    def spacer(self, hbox, xstr = "    ", expand = False):
        lab = gtk.Label(xstr)
        hbox.pack_start(lab, expand)
       
    def vspacer(self, vbox, xstr = "     ", expand = False):
        lab = gtk.Label(xstr)
        vbox.pack_start(lab, expand )
        
    def click_ok(self, butt, xx):
        err = self.cback(self)
        if err == "":
            self.ok = True
            self.destroy()
        else:
            sutil.message("Operator entry incomplete.\n\n" + err, self)
        pass
        
    def click_can(self, butt, xx):
        self.destroy()
        pass
    
    def key_press_event(self, win, event):
        if event.keyval == gtk.keysyms.Escape:
            self.destroy()
        #print "keystate", event.state
        if event.keyval == gtk.keysyms.x and event.state & gtk.gdk.MOD1_MASK:
            self.destroy()
    
    def  area_button(self, butt):
        pass
    
    def scrolledtext(self, name, body = None):
        textx = gtk.TextView();
        textx.set_border_width(4)
        self.arr.append((name, textx))
        if body != None: 
            self.text.grab_focus()
            buff = gtk.TextBuffer(); buff.set_text(body)
            self.text.set_buffer(buff)

        sw = gtk.ScrolledWindow()
        sw.add(textx)
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        return sw
    
    # Expects two tuples of stuff
    # labtext, labname, tip, defval = None: 
    
    def entryquad(self, vbox, entry1, entry2):
    
        hbox2 = gtk.HBox()
        
        lab1a = gtk.Label("      ")
        hbox2.pack_start(lab1a, False)
        lab1 = gtk.Label(entry1[0]) ; lab1.set_alignment(1, 0)
        lab1.set_tooltip_text(entry1[2])
        hbox2.pack_start(lab1, False)
        lab1a = gtk.Label("      ")
        hbox2.pack_start(lab1a, False)
        headx = gtk.Entry();
        if entry1[3] != None: 
            headx.set_text(entry1[3])
        hbox2.pack_start(headx, True)
        lab3 = gtk.Label("        ")
        hbox2.pack_start(lab3, False)
        self.arr.append((entry1[1], headx))
        
        lab1b = gtk.Label("      ")
        hbox2.pack_start(lab1b, False)
        lab2 = gtk.Label(entry2[0])  ; lab2.set_alignment(1, 0)
        lab2.set_tooltip_text(entry2[2])
        hbox2.pack_start(lab2, False)
        lab1b = gtk.Label("      ")
        hbox2.pack_start(lab1b, False)
        headx2 = gtk.Entry();
        if entry2[3] != None: 
            headx2.set_text(entry2[3])
        hbox2.pack_start(headx2, True)
        lab3b = gtk.Label("        ")
        hbox2.pack_start(lab3b, False)
        self.arr.append((entry2[1], headx2))
        self.vspacer(vbox)
        vbox.pack_start(hbox2)
        return lab1, lab2  
    
    # Create a label entry pair    
    def entrypair(self, vbox, labtext, labname, tip, defval = None): 
        
        hbox2 = gtk.HBox()
        lab1b = gtk.Label("      ")
        hbox2.pack_start(lab1b, False)
        
        lab1 = gtk.Label(labtext) ; lab1.set_alignment(1, 0)
        hbox2.pack_start(lab1, False)
        
        lab1a = gtk.Label("      ")
        hbox2.pack_start(lab1a, False)
        
        headx = gtk.Entry();
        if defval != None: 
            headx.set_text(defval)
        hbox2.pack_start(headx, True)
        lab3 = gtk.Label("        ")
        hbox2.pack_start(lab3, False)
        self.arr.append((labname, headx))
        
        self.vspacer(vbox)
        vbox.pack_start(hbox2, False)
        lab1.set_tooltip_text(tip)

        return lab1

    def textviewpair(self, vbox, labtext, labname, tip, defval = None): 
            
        hbox2 = gtk.HBox(); 
        self.spacer(hbox2)
        
        lab2a = gtk.Label("     ")
        hbox2.pack_start(lab2a, False )
        
        lab2 = gtk.Label(labtext); lab2.set_alignment(1, 0)
        lab2.set_tooltip_text(tip)
        hbox2.pack_start(lab2, False )
        sw = self.scrolledtext(labname)
        self.spacer(hbox2)
        hbox2.pack_start(sw)
        self.spacer(hbox2)
        self.vspacer(vbox)
        
        lab2b = gtk.Label("     ")
        hbox2.pack_start(lab2b, False )
        vbox.pack_start(hbox2)
        return lab2    
        
    def handler_tick(self):
        gobject.timeout_add(1000, self.handler_tick)
            
    '''wid = padding.Padding()
    wid.set_size_request(lenx, 30)
    cm = gtk.gdk.colormap_get_system() 
    col = cm.alloc_color(10, 100, 100)
    wid.modify_fg(gtk.STATE_NORMAL, col)
    wid.modify_bg(gtk.STATE_NORMAL, col)
    wid.modify_fg(gtk.STATE_ACTIVE, col)
    wid.modify_bg(gtk.STATE_ACTIVE, col)
    wid.modify_fg(gtk.STATE_INSENSITIVE, col)
    wid.modify_bg(gtk.STATE_INSENSITIVE, col)
    wid.modify_fg(gtk.STATE_SELECTED, col)
    wid.modify_bg(gtk.STATE_SELECTED, col)
    #hbox2.pack_start(wid, False)'''
    





