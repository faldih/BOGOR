import numpy as np
from PIL import Image
import os

from copy import deepcopy

import config
from libs.pconv_hybrid_model import PConvUnet
from libs.flood_fill import find_regions, expand_bounding

class Decensor():

    def __init__(self):
        self.args = config.get_args()
        self.is_mosaic = self.args.is_mosaic

        self.mask_color = [self.args.mask_color_red/255.0, self.args.mask_color_green/255.0, self.args.mask_color_blue/255.0]

        if not os.path.exists(self.args.decensor_output_path):
            os.makedirs(self.args.decensor_output_path)

        self.load_model()

    def get_mask(self, colored, width, height):
        mask = np.ones(colored.shape, np.uint8)
        for row in range(height):
            for col in range(width):
                if np.array_equal(colored[0][row][col], self.mask_color):
                    mask[0, row, col] = 0
        return mask

    def load_model(self):
        self.model = PConvUnet(weight_filepath='data/logs/')
        self.model.load(
            r"./models/model.h5",
            train_bn=False,
            lr=0.00005
        )

    def decensor_all_images_in_folder(self):
        color_dir = self.args.decensor_input_path
        file_names = os.listdir(color_dir)

        for file_name in file_names:
            color_file_path = os.path.join(color_dir, file_name)
            if os.path.isfile(color_file_path) and os.path.splitext(color_file_path)[1] == ".png":
                print("--------------------------------------------------------------------------")
                print("Decensoring the image {color_file_path}".format(color_file_path = color_file_path))
                colored_img = Image.open(color_file_path)
                if self.is_mosaic:
                    ori_dir = self.args.decensor_input_original_path
                    valid_formats = {".png", ".jpg", ".jpeg"}
                    found_valid = False
                    for valid_format in valid_formats:
                        test_file_name = os.path.splitext(file_name)[0] + valid_format
                        ori_file_path = os.path.join(ori_dir, test_file_name)
                        if os.path.isfile(ori_file_path):
                            found_valid = True
                            ori_img = Image.open(ori_file_path)
                            self.decensor_image(ori_img, colored_img, file_name)
                            continue
                    if not found_valid:
                        print("Corresponding original, uncolored image not found in {ori_file_path}. \nCheck if it exists and is in the PNG or JPG format.".format(ori_file_path = ori_file_path))
                else:
                    self.decensor_image(colored_img, colored_img, file_name)
        print("--------------------------------------------------------------------------")

    def decensor_image(self, ori, colored, file_name):
        width, height = ori.size
        has_alpha = False
        if (ori.mode == "RGBA"):
            has_alpha = True
            alpha_channel = np.asarray(ori)[:,:,3]
            alpha_channel = np.expand_dims(alpha_channel, axis =-1)
            ori = ori.convert('RGB')

        ori_array = np.asarray(ori)
        ori_array = np.array(ori_array / 255.0)
        ori_array = np.expand_dims(ori_array, axis = 0)

        if self.is_mosaic:
            mask = np.ones(ori_array.shape, np.uint8)
        else:
            mask = self.get_mask(ori_array, width, height) 

        regions = find_regions(colored.convert('RGB'))
        print("Found {region_count} censored regions in this image!".format(region_count = len(regions)))

        if len(regions) == 0 and not self.is_mosaic:
            print("No green regions detected!")
            return

        output_img_array = ori_array[0].copy()

        for region_counter, region in enumerate(regions, 1):
            bounding_box = expand_bounding(ori, region)
            crop_img = ori.crop(bounding_box)
            mask_reshaped = mask[0,:,:,:] * 255.0
            mask_img = Image.fromarray(mask_reshaped.astype('uint8'))
            crop_img = crop_img.resize((512, 512))
            crop_img_array = np.asarray(crop_img)
            crop_img_array = crop_img_array / 255.0
            crop_img_array = np.expand_dims(crop_img_array, axis = 0)
            mask_img = mask_img.crop(bounding_box)
            mask_img = mask_img.resize((512, 512))

            mask_array = np.asarray(mask_img)
            mask_array = np.array(mask_array / 255.0)
            mask_array[mask_array > 0] = 1
            mask_array = np.expand_dims(mask_array, axis = 0)

            pred_img_array = self.model.predict([crop_img_array, mask_array, mask_array])
            
            pred_img_array = pred_img_array * 255.0
            pred_img_array = np.squeeze(pred_img_array, axis = 0)

            bounding_width = bounding_box[2]-bounding_box[0]
            bounding_height = bounding_box[3]-bounding_box[1]
            pred_img = Image.fromarray(pred_img_array.astype('uint8'))
            pred_img = pred_img.resize((bounding_width, bounding_height), resample = Image.BICUBIC)
            pred_img_array = np.asarray(pred_img)
            pred_img_array = pred_img_array /255.0
            pred_img_array = np.expand_dims(pred_img_array, axis = 0)

            for i in range(len(ori_array)):
                for col in range(bounding_width):
                    for row in range(bounding_height):
                        bounding_width_index = col + bounding_box[0]
                        bounding_height_index = row + bounding_box[1]
                        if (bounding_width_index, bounding_height_index) in region:
                            output_img_array[bounding_height_index][bounding_width_index] = pred_img_array[i,:,:,:][row][col]
            print("{region_counter} out of {region_count} regions decensored.".format(region_counter=region_counter, region_count=len(regions)))

        output_img_array = output_img_array * 255.0

            output_img_array = np.concatenate((output_img_array, alpha_channel), axis = 2)

        output_img = Image.fromarray(output_img_array.astype('uint8'))

        save_path = os.path.join(self.args.decensor_output_path, file_name)
        output_img.save(save_path)

        print("Decensored image saved to {save_path}!".format(save_path=save_path))
        return

if __name__ == '__main__':
    decensor = Decensor()
decensor.decensor_all_images_in_folder()
import argparse

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1', True):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0', False):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def get_args():
	parser = argparse.ArgumentParser(description='')

	parser.add_argument('--decensor_input_path', dest='decensor_input_path', default='./decensor_input/', help='input images with censored regions colored green to be decensored by decensor.py path')
	parser.add_argument('--decensor_input_original_path', dest='decensor_input_original_path', default='./decensor_input_original/', help='input images with no modifications to be decensored by decensor.py path')
	parser.add_argument('--decensor_output_path', dest='decensor_output_path', default='./decensor_output/', help='output images generated from running decensor.py path')

	parser.add_argument('--mask_color_red', dest='mask_color_red', default=0, help='red channel of mask color in decensoring')
	parser.add_argument('--mask_color_green', dest='mask_color_green', default=255, help='green channel of mask color in decensoring')
	parser.add_argument('--mask_color_blue', dest='mask_color_blue', default=0, help='blue channel of mask color in decensoring')

	parser.add_argument('--is_mosaic', dest='is_mosaic', default='False', type=str2bool, help='true if image has mosaic censoring, false otherwise')

	args = parser.parse_args()
	return args

if __name__ == '__main__':
get_args()
def __init__(self, root):
        super().__init__(root)
        
        self.drawn_img = None
        self.screen_width = root.winfo_screenwidth()
        self.screen_height = root.winfo_screenheight()
        self.start_x, self.start_y = 0, 0
        self.end_x, self.end_y = 0, 0
        self.current_item = None
        self.fill = "#00ff00"
        self.fill_pil = (0,255,0,255)
        self.outline = "#00ff00"
        self.brush_width = 2
        self.background = 'white'
        self.foreground = "#00ff00"
        self.file_name = "Untitled"
        self.tool_bar_functions = (
            "draw_line", "draw_irregular_line"
        )
        self.selected_tool_bar_function = self.tool_bar_functions[0]
        
        self.create_gui()
        self.bind_mouse()

    def on_new_file_menu_clicked(self, event=None):
        self.start_new_project()

    def start_new_project(self):
        self.canvas.delete(tk.ALL)
        self.canvas.config(bg="#ffffff")
        self.root.title('untitled')

    def on_open_image_menu_clicked(self, event=None):
        self.open_image()

    def open_image(self):
        self.file_name = filedialog.askopenfilename(master=self.root, filetypes = [("All Files","*.*")], title="Open...")
        print(self.file_name)
        self.canvas.img = Image.open(self.file_name)
        self.canvas.img_width, self.canvas.img_height = self.canvas.img.size
        self.canvas.tk_img = ImageTk.PhotoImage(self.canvas.img)
        self.canvas.config(width=self.canvas.img_width, height=self.canvas.img_height)
        self.canvas.create_image(self.canvas.img_width/2.0,self.canvas.img_height/2.0,image=self.canvas.tk_img)

        self.drawn_img = Image.new("RGBA", self.canvas.img.size)
        self.drawn_img_draw = ImageDraw.Draw(self.drawn_img)


    def on_import_mask_clicked(self, event=None):
        self.import_mask()

    def display_canvas(self):
        composite_img = Image.alpha_composite(self.canvas.img.convert('RGBA'), self.drawn_img).convert('RGB')
        self.canvas.tk_img = ImageTk.PhotoImage(composite_img)

        self.canvas.create_image(self.canvas.img_width/2.0,self.canvas.img_height/2.0,image=self.canvas.tk_img)

    def import_mask(self):
        file_name_mask = filedialog.askopenfilename(master=self.root, filetypes = [("All Files","*.*")], title="Import mask...")
        mask_img = Image.open(file_name_mask)
        if (mask_img.size != self.canvas.img.size):
            messagebox.showerror("Import mask", "Mask image size does not match the original image size! Mask image not imported.")
            return
        self.drawn_img = mask_img
        self.drawn_img_draw = ImageDraw.Draw(self.drawn_img)
        self.display_canvas()

    def on_save_menu_clicked(self, event=None):
        if self.file_name == 'untitled':
            self.on_save_as_menu_clicked()
        else:
            self.actual_save()

    def on_save_as_menu_clicked(self):
        file_name = filedialog.asksaveasfilename(
            master=self.root, filetypes=[('All Files', ('*.ps', '*.ps'))], title="Save...")
        if not file_name:
            return
        self.file_name = file_name
        self.actual_save()

    def actual_save(self):
        self.canvas.postscript(file=self.file_name, colormode='color')
        self.root.title(self.file_name)

    def on_close_menu_clicked(self):
        self.close_window()

    def close_window(self):
        if messagebox.askokcancel("Quit", "Do you really want to quit?"):
            self.root.destroy()

    def on_undo_menu_clicked(self, event=None):
        self.undo()

    def undo(self):
        items_stack = list(self.canvas.find("all"))
        try:
            last_item_id = items_stack.pop()
        except IndexError:
            return
        self.canvas.delete(last_item_id)

    def on_canvas_zoom_in_menu_clicked(self):
        self.canvas_zoom_in()

    def on_canvas_zoom_out_menu_clicked(self):
        self.canvas_zoom_out()

    def canvas_zoom_in(self):
        self.canvas.scale("all", 0, 0, 1.2, 1.2)
        self.canvas.config(scrollregion=self.canvas.bbox(tk.ALL))
        self.canvas.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.BOTH)

    def canvas_zoom_out(self):
        self.canvas.scale("all", 0, 0, .8, .8)
        self.canvas.config(scrollregion=self.canvas.bbox(tk.ALL))
        self.canvas.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.BOTH)

    def on_decensor_menu_clicked(self, event=None):
        combined_img = Image.alpha_composite(self.canvas.img.convert('RGBA'), self.drawn_img)
        decensorer = decensor.Decensor()
        decensorer.decensor_image(combined_img.convert('RGB'), self.file_name + ".png")
        messagebox.showinfo(
           "Decensoring", "Decensoring complete!")

    def on_about_menu_clicked(self, event=None):
        messagebox.showinfo(
           "About", "Tkinter GUI Application\n Development Blueprints")

    def get_all_configurations_for_item(self):
        configuration_dict = {}
        for key, value in self.canvas.itemconfig("current").items():
            if value[-1] and value[-1] not in ["0", "0.0", "0,0", "current"]:
                configuration_dict[key] = value[-1]
        return configuration_dict

    def canvas_function_wrapper(self, function_name, *arg, **kwargs):
        func = getattr(self.canvas, function_name)
        func(*arg, **kwargs)

    def adjust_canvas_coords(self, x_coordinate, y_coordinate):
        
        low_x, high_x = self.x_scroll.get()
        low_y, high_y = self.y_scroll.get()
        
        return low_x * 800 + x_coordinate, low_y * 800 + y_coordinate

    def create_circle(self, x, y, r, **kwargs):
        return self.canvas.create_oval(x-r, y-r, x+r, y+r, **kwargs)

    def draw_irregular_line(self):
        self.drawn_img_draw.line((self.start_x, self.start_y, self.end_x, self.end_y), fill=self.fill_pil, width=int(self.brush_width))
        self.drawn_img_draw.ellipse((self.end_x - self.brush_width/2.0, self.end_y - self.brush_width/2.0, self.end_x + self.brush_width/2.0, self.end_y + self.brush_width/2.0), fill=self.fill_pil)

        self.display_canvas()

        self.canvas.bind("<B1-Motion>", self.draw_irregular_line_update_x_y)

    def draw_irregular_line_update_x_y(self, event=None):
        self.start_x, self.start_y = self.end_x, self.end_y
        self.end_x, self.end_y = self.adjust_canvas_coords(event.x, event.y)
        self.draw_irregular_line()

    def draw_irregular_line_options(self):
        self.create_fill_options_combobox()
        self.create_width_options_combobox()

    def on_tool_bar_button_clicked(self, button_index):
        self.selected_tool_bar_function = self.tool_bar_functions[button_index]
        self.remove_options_from_top_bar()
        self.display_options_in_the_top_bar()
        self.bind_mouse()

    def float_range(self, x, y, step):
        while x < y:
            yield x
            x += step

    def set_foreground_color(self, event=None):
        self.foreground = self.get_color_from_chooser(
            self.foreground, "foreground")
        self.color_palette.itemconfig(
            self.foreground_palette, width=0, fill=self.foreground)

    def set_background_color(self, event=None):
        self.background = self.get_color_from_chooser(
            self.background, "background")
        self.color_palette.itemconfig(
            self.background_palette, width=0, fill=self.background)

    def get_color_from_chooser(self, initial_color, color_type="a"):
        color = colorchooser.askcolor(
            color=initial_color,
            title="select {} color".format(color_type)
        )[-1]
        if color:
            return color
        else:
            return initial_color

    def try_to_set_fill_after_palette_change(self):
        try:
            self.set_fill()
        except:
            pass

    def try_to_set_outline_after_palette_change(self):
        try:
            self.set_outline()
        except:
            pass

    def display_options_in_the_top_bar(self):
        self.show_selected_tool_icon_in_top_bar(
            self.selected_tool_bar_function)
        options_function_name = "{}_options".format(self.selected_tool_bar_function)
        func = getattr(self, options_function_name, self.function_not_defined)
        func()

    def draw_line_options(self):
        self.create_fill_options_combobox()
        self.create_width_options_combobox()

    def create_fill_options_combobox(self):
        tk.Label(self.top_bar, text='Fill:').pack(side="left")
        self.fill_combobox = ttk.Combobox(
            self.top_bar, state='readonly', width=5)
        self.fill_combobox.pack(side="left")
        self.fill_combobox['values'] = ('none', 'fg', 'bg', 'black', 'white')
        self.fill_combobox.bind('<<ComboboxSelected>>', self.set_fill)
        self.fill_combobox.set(self.fill)

    def create_outline_options_combobox(self):
        tk.Label(self.top_bar, text='Outline:').pack(side="left")
        self.outline_combobox = ttk.Combobox(
            self.top_bar, state='readonly', width=5)
        self.outline_combobox.pack(side="left")
        self.outline_combobox['values'] = (
            'none', 'fg', 'bg', 'black', 'white')
        self.outline_combobox.bind('<<ComboboxSelected>>', self.set_outline)
        self.outline_combobox.set(self.outline)

    def create_width_options_combobox(self):
        tk.Label(self.top_bar, text='Width:').pack(side="left")
        self.width_combobox = ttk.Combobox(
            self.top_bar, state='readonly', width=3)
        self.width_combobox.pack(side="left")
        self.width_combobox['values'] = (
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50)
        self.width_combobox.bind('<<ComboboxSelected>>', self.set_brush_width)
        self.width_combobox.set(self.brush_width)

    def set_fill(self, event=None):
        fill_color = self.fill_combobox.get()
        if fill_color == 'none':
            self.fill = '' 
        elif fill_color == 'fg':
            self.fill = self.foreground
        elif fill_color == 'bg':
            self.fill = self.background
        else:
            self.fill = fill_color

    def set_outline(self, event=None):
        outline_color = self.outline_combobox.get()
        if outline_color == 'none':
            self.outline = ''
        elif outline_color == 'fg':
            self.outline = self.foreground
        elif outline_color == 'bg':
            self.outline = self.background
        else:
            self.outline = outline_color

    def set_brush_width(self, event):
        self.brush_width = float(self.width_combobox.get())

    def create_color_palette(self):
        self.color_palette = tk.Canvas(self.tool_bar, height=55, width=55)
        self.color_palette.grid(row=10, column=1, columnspan=2, pady=5, padx=3)
        self.background_palette = self.color_palette.create_rectangle(
            15, 15, 48, 48, outline=self.background, fill=self.background)
        self.foreground_palette = self.color_palette.create_rectangle(
            1, 1, 33, 33, outline=self.foreground, fill=self.foreground)
        self.bind_color_palette()

    def bind_color_palette(self):
        self.color_palette.tag_bind(
            self.background_palette, "<Button-1>", self.set_background_color)
        self.color_palette.tag_bind(
            self.foreground_palette, "<Button-1>", self.set_foreground_color)

    def create_current_coordinate_label(self):
        self.current_coordinate_label = tk.Label(
            self.tool_bar, text='x:0\ny: 0 ')
        self.current_coordinate_label.grid(
            row=13, column=1, columnspan=2, pady=5, padx=1, sticky='w')

    def show_current_coordinates(self, event=None):
        x_coordinate = event.x
        y_coordinate = event.y
        coordinate_string = "x:{0}\ny:{1}".format(x_coordinate, y_coordinate)
        self.current_coordinate_label.config(text=coordinate_string)

    def function_not_defined(self):
        pass

    def execute_selected_method(self):
        self.current_item = None
        func = getattr(
            self, self.selected_tool_bar_function, self.function_not_defined)
        func()

    def draw_line(self):
        self.current_item = self.canvas.create_line(
            self.start_x, self.start_y, self.end_x, self.end_y, fill=self.fill, width=self.brush_width)

    def create_tool_bar_buttons(self):
        for index, name in enumerate(self.tool_bar_functions):
            icon = tk.PhotoImage(file='icons/' + name + '.gif')
            self.button = tk.Button(
                self.tool_bar, image=icon, command=lambda index=index: self.on_tool_bar_button_clicked(index))
            self.button.grid(
                row=index // 2, column=1 + index % 2, sticky='nsew')
            self.button.image = icon

    def remove_options_from_top_bar(self):
        for child in self.top_bar.winfo_children():
            child.destroy()

    def show_selected_tool_icon_in_top_bar(self, function_name):
        display_name = function_name.replace("_", " ").capitalize() + ":"
        tk.Label(self.top_bar, text=display_name).pack(side="left")
        photo = tk.PhotoImage(
            file='icons/' + function_name + '.gif')
        label = tk.Label(self.top_bar, image=photo)
        label.image = photo
        label.pack(side="left")

    def bind_mouse(self):
        self.canvas.bind("<Button-1>", self.on_mouse_button_pressed)
        self.canvas.bind(
            "<Button1-Motion>", self.on_mouse_button_pressed_motion)
        self.canvas.bind(
            "<Button1-ButtonRelease>", self.on_mouse_button_released)
        self.canvas.bind("<Motion>", self.on_mouse_unpressed_motion)

    def on_mouse_button_pressed(self, event):
        self.start_x = self.end_x = self.canvas.canvasx(event.x)
        self.start_y = self.end_y = self.canvas.canvasy(event.y)
        self.execute_selected_method()

    def on_mouse_button_pressed_motion(self, event):
        self.end_x = self.canvas.canvasx(event.x)
        self.end_y = self.canvas.canvasy(event.y)
        self.canvas.delete(self.current_item)
        self.execute_selected_method()

    def on_mouse_button_released(self, event):
        self.end_x = self.canvas.canvasx(event.x)
        self.end_y = self.canvas.canvasy(event.y)

    def on_mouse_unpressed_motion(self, event):
        self.show_current_coordinates(event)

    def create_gui(self):
        self.create_menu()
        self.create_top_bar()
        self.create_tool_bar()
        self.create_tool_bar_buttons()
        self.create_drawing_canvas()
        self.create_color_palette()
        self.create_current_coordinate_label()
        self.bind_menu_accelrator_keys()
        self.show_selected_tool_icon_in_top_bar("draw_line")
        self.draw_line_options()

    def create_menu(self):
        self.menubar = tk.Menu(self.root)
        menu_definitions = (
            'File- &New/Ctrl+N/self.on_new_file_menu_clicked, Open/Ctrl+O/self.on_open_image_menu_clicked, Import Mask/Ctrl+M/self.on_import_mask_clicked, Save/Ctrl+S/self.on_save_menu_clicked, SaveAs/ /self.on_save_as_menu_clicked, sep, Exit/Alt+F4/self.on_close_menu_clicked',
            'Edit- Undo/Ctrl+Z/self.on_undo_menu_clicked, sep',
            'View- Zoom in//self.on_canvas_zoom_in_menu_clicked,Zoom Out//self.on_canvas_zoom_out_menu_clicked',
            'Decensor- Decensor/Ctrl+D/self.on_decensor_menu_clicked',
            'About- About/F1/self.on_about_menu_clicked'
        )
        self.build_menu(menu_definitions)

    def create_top_bar(self):
        self.top_bar = tk.Frame(self.root, height=25, relief="raised")
        self.top_bar.pack(fill="x", side="top", pady=2)

    def create_tool_bar(self):
        self.tool_bar = tk.Frame(self.root, relief="raised", width=50)
        self.tool_bar.pack(fill="y", side="left", pady=3)

    def create_drawing_canvas(self):
        self.canvas_frame = tk.Frame(self.root, width=900, height=900)
        self.canvas_frame.pack(side="right", expand="yes", fill="both")
        self.canvas = tk.Canvas(self.canvas_frame, background="white",
                                width=512, height=512, scrollregion=(0, 0, 512, 512))
        self.create_scroll_bar()
        self.canvas.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.BOTH)

        self.canvas.img = Image.open('./icons/canvas_top_test.png').convert('RGBA')
        self.canvas.img = self.canvas.img.resize((512,512))
        self.canvas.tk_img = ImageTk.PhotoImage(self.canvas.img)
        self.canvas.create_image(256,256,image=self.canvas.tk_img)

    def create_scroll_bar(self):
        self.x_scroll = tk.Scrollbar(self.canvas_frame, orient="horizontal")
        self.x_scroll.pack(side="bottom", fill="x")
        self.x_scroll.config(command=self.canvas.xview)
        self.y_scroll = tk.Scrollbar(self.canvas_frame, orient="vertical")
        self.y_scroll.pack(side="right", fill="y")
        self.y_scroll.config(command=self.canvas.yview)
        self.canvas.config(
            xscrollcommand=self.x_scroll.set, yscrollcommand=self.y_scroll.set)

    def bind_menu_accelrator_keys(self):
        self.root.bind('<KeyPress-F1>', self.on_about_menu_clicked)
        self.root.bind('<Control-N>', self.on_new_file_menu_clicked)
        self.root.bind('<Control-n>', self.on_new_file_menu_clicked)
        self.root.bind('<Control-s>', self.on_save_menu_clicked)
        self.root.bind('<Control-S>', self.on_save_menu_clicked)
        self.root.bind('<Control-z>', self.on_undo_menu_clicked)
        self.root.bind('<Control-Z>', self.on_undo_menu_clicked)

if __name__ == '__main__':
    root = tk.Tk()
    app = PaintApplication(root)
root.mainloop()
import pandas as pd
import numpy as np
import logging

graph_global_fns = ['update_globals', 'dump', 'remove_global_flags']

class Graph:
    xlabel = None
    xscale = None
    xrange = None
    ylabel = None
    yscale = None
    yrange = None
    title = None
    figsize = None
    fontsize = None
    tick_fontsize = None
    label_fontsize = None
    xtick_fontsize = None
    ytick_fontsize = None
    xlabel_fontsize = None
    ylabel_fontsize = None
    xtick_angle = None
    ytick_angle = None
    xtick_align = None
    ytick_align = None
    def __init__(self):
        self.xcol = None
        self.ycol = None
        self.legend = None
        self.color = None
        self.style = None
        self.marker = None
        self.width = None
        self.offset = None
        self.markersize = None
        self.output = None
        self.time_format = None
        self.resample = None
        self.sort = None
        self.bar = None
        self.barh = None
    def __str__(self):
        return str(self.__data__())
    def __repr__(self):
        return self.__str__()
    def __data__(self):
        data = {'globals': {}, 'attributes': {}}
        for attr in [y for y in dir(Graph)
                if not (y.startswith('__') and y.endswith('__'))]:
            if attr in graph_global_fns: continue
            data['globals'][attr] = getattr(Graph, attr)
        for attr in [y for y in dir(self)
                if not (y.startswith('__') and y.endswith('__'))]:
            if attr in graph_global_fns: continue
            if attr in data['globals']: continue
            data['attributes'][attr] = getattr(self, attr)
        data['attributes']['xcol'] = str(data['attributes']['xcol']).split('\n')[-1]
        data['attributes']['ycol'] = str(data['attributes']['ycol']).split('\n')[-1]
        return data
    @staticmethod
    def update_globals(args):
        for attr in [y for y in dir(Graph)
                if not (y.startswith('__') and y.endswith('__'))]:
            if attr in graph_global_fns: continue
            if attr not in dir(args): continue
            val = getattr(args, attr)
            cur = getattr(Graph, attr)
            if cur is None:
                setattr(Graph, attr, val)
            if type(cur) is tuple and not cur[1]:
                setattr(Graph, attr, val)
            if type(cur) is tuple and cur[1] and type(val) is tuple and val[1]:
                setattr(Graph, attr, val)
    @staticmethod
    def dump(graphs):
        return (graphs, graphs[0].__data__()['globals'])
    @staticmethod
    def remove_global_flags():
        for attr in [y for y in dir(Graph)
                if not (y.startswith('__') and y.endswith('__'))]:
            if attr in graph_global_fns: continue
            val = getattr(Graph, attr)
            if type(val) is tuple:
                setattr(Graph, attr, val[0])

def get_graph_def(xcol, ycol, legend, color, style, marker, width,
        offset, markersize, output, time_format, resample, sort, bar, barh):
    timeseries = False
    try:
        if time_format is not None:
            xcol = pd.to_datetime(xcol, format=time_format)
            timeseries = True
        elif xcol.dtype == np.dtype('O'):
            xcol = pd.to_datetime(xcol)
            timeseries = True
    except: pass

    if sort:
        df = pd.DataFrame({xcol.name: xcol, ycol.name: ycol})
        df.sort_values(xcol.name, inplace=True)
        xcol, ycol = df[xcol.name], df[ycol.name]
    if resample:
        df = pd.DataFrame({xcol.name: xcol, ycol.name: ycol})
        try:
            if timeseries:
                df.set_index(xcol, inplace=True)

                df = df.resample(resample).mean().dropna()
                df.reset_index(inplace=True)
            else:
                x_min, x_max = df[xcol.name].min(), df[xcol.name].max()
                resample = float(resample)
                bins = np.linspace(x_min + resample/2, x_max - resample/2, float(x_max - x_min + resample)/resample)
                df = df.groupby(np.digitize(df[xcol.name], bins)).mean().dropna()
                del x_min, x_max, bins
        except Exception as e:
            logging.error('Error: Could not resample. "%s"' % str(e))
            exit(1)
        xcol, ycol = df[xcol.name], df[ycol.name]
        del df
    del timeseries

    kvs = locals()
    g = Graph()
    for attr, val in kvs.items():
        setattr(g, attr, val)
    return g

def get_graph_defs(args):
    graphs, globals = read_chain(args)
    class AttrDict(dict):
        def __init__(self, *args, **kwargs):
            super(AttrDict, self).__init__(*args, **kwargs)
            self.__dict__ = self
    Graph.update_globals(AttrDict(globals))

    for g in zip(args.xcol, args.ycol, args.legend, args.color, args.style,
            args.marker, args.width, args.offset, args.markersize, args.output,
            args.time_format, args.resample, args.sort, args.bar, args.barh):
        graphs += [get_graph_def(*g)]

    return graphs

def read_chain(args):
    chain = ([], {})
    if not stdin.isatty() and args.file != stdin:
        chain = pickle.loads(stdin.buffer.read())

    assert(type(chain) is tuple)
    assert(len(chain) == 2)
    assert(type(chain[0]) is list)
    assert(type(chain[1]) is dict)
    for link in chain[0]:
        assert(type(link) is Graph)

    return chain

def create_graph(graphs):
    Graph.remove_global_flags()

    if graphs[-1].output:
        import matplotlib
        matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(Graph.figsize))

    for graph in graphs:
        if graph.bar:
            x = np.arange(len(graph.xcol))
            ax.bar(x + graph.offset, graph.ycol, align='center',
                label=graph.legend, color=graph.color, width=graph.width)
            plt.xticks(x, graph.xcol)
        elif graph.barh:
            x = np.arange(len(graph.xcol))
            ax.barh(x + graph.offset, graph.ycol, align='center',
                label=graph.legend, color=graph.color, height=graph.width)
            plt.yticks(x, graph.xcol)
        else:
            ax.plot(graph.xcol, graph.ycol, label=graph.legend,
                marker=graph.marker, color=graph.color, linestyle=graph.style,
                linewidth=graph.width, markersize=graph.markersize)
        if graph.output:
            apply_globals(plt, ax)
            plt.savefig(graph.output)
        elif graph == graphs[-1]:
            apply_globals(plt, ax)
            plt.show()

def apply_globals(plt, ax):
    if Graph.tick_fontsize is not None:
        Graph.xtick_fontsize = Graph.tick_fontsize
        Graph.ytick_fontsize = Graph.tick_fontsize
    if Graph.label_fontsize is not None:
        Graph.xlabel_fontsize = Graph.label_fontsize
        Graph.ylabel_fontsize = Graph.label_fontsize
    plt.xlabel(Graph.xlabel, fontsize=Graph.xlabel_fontsize)
    plt.ylabel(Graph.ylabel, fontsize=Graph.ylabel_fontsize)
    plt.title(Graph.title)
    plt.setp(ax.get_xticklabels(), fontsize=Graph.xtick_fontsize,
        rotation=Graph.xtick_angle, horizontalalignment=Graph.xtick_align)
    plt.setp(ax.get_yticklabels(), fontsize=Graph.ytick_fontsize,
        rotation=Graph.ytick_angle, verticalalignment=Graph.ytick_align)

    if Graph.xscale is not None:
        plt.xticks(np.arange(round(ax.get_xlim()[0] / Graph.xscale) *
            Graph.xscale, ax.get_xlim()[1], Graph.xscale))
    if Graph.yscale is not None:
        plt.yticks(np.arange(round(ax.get_ylim()[0] / Graph.yscale) *
            Graph.yscale, ax.get_ylim()[1], Graph.yscale))
    if Graph.xrange is not None:
        plt.xlim(*Graph.xrange)
    if Graph.yrange is not None:
        plt.ylim(*Graph.yrange)

    plt.grid(True, alpha=0.5, linestyle='-.')
plt.legend()
class BufferOutput:

    def __init__(self, cols=70):
        self.cols = cols
        self.lines = []
        self.x = 0
        self.y = 0

    def write(self, text):
        while len(self.lines) <= self.y:
            self._append_line()
        line = self.lines[self.y]

        for tok, value in _parse_ansi(text):
            if tok == 'nl':
                self.y += 1
                self.x = 0
                if len(self.lines) <= self.y:
                    self._append_line()
                line = self.lines[self.y]
            elif tok == 'cr':
                self.x = 0
            elif tok == 'up':
                self.y = max(0, self.y - value)
                line = self.lines[self.y]
            elif tok == 'down':
                self.y = min(len(self.lines)-1, self.y + value)
                line = self.lines[self.y]
            elif tok == 'ch':
                line.seek(self.x)
                max_len = self.cols - self.x
                if len(value) > max_len:
                    value = value[:max_len]
                line.write(value)
                self.x += len(value)

    def flush(self):
        pass

    def getvalue(self):
        return "\n".join([line.getvalue().rstrip() for line in self.lines])

    def _append_line(self):
        self.lines.append(io.StringIO(str(" " * self.cols)))


def _parse_ansi(text):
    chars = io.StringIO()
    tok = None
    ix = 0
    while ix < len(text):
        if text[ix:].startswith("\033["):
            res1 = re.match(r"^([0-9]*)([AB])", text[ix+2:])
            res2 = re.match(r"^([0-9;]*)m", text[ix+2:])

            if res1:
                length = res1.end() - res1.start() + 2
                value = int(res1.group(1))
                if res1.group(2) == 'A':
                    tok = ('up', value)
                else:
                    tok = ('down', value)
                ix += length
            elif res2:
                length = res2.end() - res2.start() + 2
                value = res2.group(1)
                tok = ('color', value)
                ix += length
            else:
                chars.write(text[ix])
                ix += 1

        elif text[ix] == "\n":
            tok = ('nl', None)
            ix += 1
        elif text[ix] == "\r":
            tok = ('cr', None)
            ix += 1
        else:
            chars.write(text[ix])
            ix += 1

        if tok:
            if len(chars.getvalue()):
                yield ('ch', chars.getvalue())
                chars = io.StringIO()

            yield tok
            tok = None

    if len(chars.getvalue()):
        yield ('ch', chars.getvalue())


class ProgressBar:

    def __init__(self,
                 iterable=None,
                 epochs=None,
                 steps=None,
                 title=None,
                 style='default',
                 label="it",
                 file=sys.stdout,
                 width=70,
                 color=None,
                 keep=True,
                 show=True,
                 post=None):
        assert hasattr(iterable, '__len__') or steps is not None
        assert (isinstance(style, str) and len(style) == 1) or \
               isinstance(style, list) or \
               style in ('default', 'ascii', 'consolas')
        
        if style == 'default':
            self.style = ["", "▏","▎","▍","▌","▋","▊","▉","█"]
        elif style == 'consolas':
            self.style = ["", "▌","▌","▌","▌","█","█","█","█"]
        elif style == 'ascii':
            self.style = ["", "1","2","3","4","5","6","7","8","9","#"]
        elif isinstance(style, str):
            self.style = ["", "1","2","3","4","5","6","7","8","9", style]  
        else:
            self.style = style
        
        self.steps = steps if steps is not None else len(iterable)
        self.iterable = iter(iterable) if iterable else None
        self.epochs = epochs
        self.current_epoch = 0
        self.started = False
        self.step = 0
        self.file = file
        self.title = title
        self.label = label
        self.width = width
        self.last_it = []
        self.color = color
        self.it_per_sec = "-".rjust(6)
        self.keep = keep
        self.show = show
        self.post = post

    def start(self):
        if not self.started:
            self.started = True
            self.display()
    
    def stop(self):
        if self.show:
            if self.keep:
                print("", file=self.file)
            else:
                self.file.write("\r")
                self.file.write(str(" " * self.width))
                self.file.write("\r")
                self.file.flush()

    def __iter__(self):
        assert self.iterable
        assert not self.epochs, "total epochs not supported when used as iterator"
        return self
    
    def __next__(self):
        self.start()
        self._calc_it_per_sec()
        self.step += 1
        self.display()
        try:
            return next(self.iterable)
        except StopIteration as err:
            self.stop()
            raise err
    
    def _calc_it_per_sec(self):
        now = time.time()
        
        if not self.last_it:
            self.last_it.append(now)
        else:
            self.last_it.append(now)
            if len(self.last_it) >= 100:
                self.last_it = self.last_it[-100:]

            intervals = list(map(lambda t: t[1] - t[0], zip(self.last_it[:-1], self.last_it[1:])))
            delta = sum(intervals) / len(intervals)
            if delta != 0.:
                it_per_sec = 1.0 / delta
                if it_per_sec > 1_000_00:
                    self.it_per_sec = "{}M".format(int(it_per_sec/1_000_000))
                elif it_per_sec > 1_000:
                    self.it_per_sec = "{}K".format(int(it_per_sec/1_000))
                else:
                    self.it_per_sec = "{:.2f}".format(it_per_sec)
         
                self.it_per_sec = self.it_per_sec.rjust(6)

    def display(self):
        if not self.started or not self.show:
            return
        step = min(self.steps, self.step+1)
        
        buffer = io.StringIO()
        perc = step / self.steps
        pre = self.title
        if not pre and self.epochs:
            epoch = min(self.current_epoch + 1, self.epochs)
            pre = "Epoch " + str(epoch).rjust(len(str(self.epochs))) + "/" + str(self.epochs)
        if not pre:
            pre = '{:>3}%'.format(int(perc * 100))
        
        
        if self.post:
            post = self.post()
        else:
            post = " " + str(step).rjust(len(str(self.steps))) + "/" + str(self.steps)
            post += " [" + (self.it_per_sec or "-") + " " + self.label + "/sec]" 

        bar_length = self.width - len(pre) - len(post) - 2 

        v = perc * bar_length
        x = math.floor(v) 
        y = v - x         
        base = 1 / (len(self.style) - 1)
        prec = 3
        i = int(round(base*math.floor(float(y)/base),prec)/base)
        bar = "" + self.style[-1]*x + self.style[i]
        n = bar_length-len(bar)
        bar = bar + " "*n
        if self.color:
            bar = f"\033[{self.color}m{bar}\033[0m"
            
        buffer.write("\r")
        buffer.write(pre)
        buffer.write('|')
        buffer.write(bar)
        buffer.write("|")
        buffer.write(post)

        self.file.write(buffer.getvalue())
        self.file.flush()
      

    def update(self, step=None, epoch=None):
        self._calc_it_per_sec()
        if step is not None:
            self.step = step
        
        if epoch is not None:
            self.current_epoch = epoch
        
        self.display()


_DEFAULT_HEIGHT = 24
_DEFAULT_WIDTH = 79
if os.name == 'nt':
    import ctypes
    from ctypes import LibraryLoader
    windll = LibraryLoader(ctypes.WinDLL)
    from ctypes import wintypes, byref, Structure, POINTER, c_ulong, c_buffer, sizeof, cast
    COORD = wintypes._COORD

    _LF_FACESIZE = 32

    class CONSOLE_SCREEN_BUFFER_INFO(Structure):
        """struct in wincon.h."""
        _fields_ = [
            ("dwSize", COORD),
            ("dwCursorPosition", COORD),
            ("wAttributes", wintypes.WORD),
            ("srWindow", wintypes.SMALL_RECT),
            ("dwMaximumWindowSize", COORD),
        ]
    
    class CONSOLE_FONT_INFOEX(Structure):
        _fields_ = [
            ("cbSize", wintypes.ULONG),
            ("nFont", wintypes.DWORD),
            ("dwFontSize", COORD),
            ("FontFamily", wintypes.UINT),
            ("FontWeight", wintypes.UINT),
            ("FaceName", wintypes.WCHAR * _LF_FACESIZE)
        ]

    class WINAPI:
        
        _GetStdHandle = windll.kernel32.GetStdHandle
        _GetStdHandle.argtypes = [wintypes.DWORD]
        _GetStdHandle.restype = wintypes.HANDLE

        _GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo
        _GetConsoleScreenBufferInfo.argtypes = [wintypes.HANDLE, POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
        _GetConsoleScreenBufferInfo.restype = wintypes.BOOL

        _EnumProcesses = windll.psapi.EnumProcesses
        _EnumProcesses.argtypes = [wintypes.PDWORD, wintypes.DWORD, wintypes.PDWORD]
        _EnumProcesses.restype = wintypes.BOOL

        _EnumProcessModules = windll.psapi.EnumProcessModules
        _EnumProcessModules.argtypes = [wintypes.HANDLE, POINTER(wintypes.HANDLE), wintypes.DWORD, POINTER(wintypes.LPDWORD)]
        _EnumProcessModules.restype = wintypes.BOOL

        _OpenProcess = windll.kernel32.OpenProcess
        _OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        _OpenProcess.restype = wintypes.HANDLE

        _CloseHandle = windll.kernel32.CloseHandle
        _CloseHandle.argtypes = [wintypes.HANDLE]
        _CloseHandle.restype = wintypes.BOOL

        _GetModuleBaseNameW = windll.psapi.GetModuleBaseNameW
        _GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
        _GetModuleBaseNameW.restype = wintypes.DWORD

        _GetConsoleMode = windll.kernel32.GetConsoleMode
        _GetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.LPDWORD]
        _GetConsoleMode.restype = wintypes.BOOL

        _SetConsoleMode = windll.kernel32.SetConsoleMode
        _SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        _SetConsoleMode.restype = wintypes.BOOL

        _GetCurrentConsoleFontEx = windll.kernel32.GetCurrentConsoleFontEx
        _GetCurrentConsoleFontEx.argtypes = [wintypes.HANDLE, wintypes.BOOL, POINTER(CONSOLE_FONT_INFOEX)]
        _GetCurrentConsoleFontEx.restype = wintypes.BOOL

        _PROCESS_QUERY_INFORMATION = 0x0400
        _PROCESS_VM_READ = 0x0010
        _ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        
        
        _STDOUT = -11
        _STDERR = -12

        @staticmethod
        @lru_cache()
        def winapi_test():
            def _winapi_test(handle):
                csbi = CONSOLE_SCREEN_BUFFER_INFO()
                success = WINAPI._GetConsoleScreenBufferInfo(
                    handle, byref(csbi))
                return bool(success)

            return any(_winapi_test(h) for h in
                    (WINAPI._GetStdHandle(WINAPI._STDOUT), WINAPI._GetStdHandle(WINAPI._STDERR)))
        
        @staticmethod
        @lru_cache()
        def get_ppname():
            process_id_array_size = 1024
            entries = 0

            while entries == 0 or process_id_array_size == entries:
                dword_array = (wintypes.DWORD * process_id_array_size)

                process_ids = dword_array()
                bytes_used = wintypes.DWORD(0)

                res = WINAPI._EnumProcesses(cast(process_ids, wintypes.PDWORD), sizeof(process_ids), byref(bytes_used))
                if not res:
                    return []

                entries = int(bytes_used.value / sizeof(wintypes.DWORD))
                process_id_array_size += 512

            name = None
            index = 0
            ppid = os.getppid()
            while index < entries:
                process_id = process_ids[index]
                if ppid != process_id:
                    index += 1
                    continue
                
                
                process_handle = WINAPI._OpenProcess(WINAPI._PROCESS_QUERY_INFORMATION | WINAPI._PROCESS_VM_READ, False, process_id)
                if process_handle:
                    module = wintypes.HANDLE()
                    needed_bytes = wintypes.LPDWORD()
                    module_res = WINAPI._EnumProcessModules(
                        process_handle,
                        byref(module),
                        sizeof(module),
                        byref(needed_bytes)
                    )
                    if module_res:
                        length = 260
                        buffer = ctypes.create_unicode_buffer(length)
                        WINAPI._GetModuleBaseNameW(process_handle, module, buffer, length)
                        name = buffer.value
                WINAPI._CloseHandle(process_handle)
                break

            return name
        
        @staticmethod
        def _terminal_size(handle):
            csbi = CONSOLE_SCREEN_BUFFER_INFO()
            if not WINAPI._GetConsoleScreenBufferInfo(handle, byref(csbi)):
                raise ctypes.WinError()  # Subclass of OSError.
            else:
                columns = csbi.srWindow.Right - csbi.srWindow.Left + 1
                rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1
                return columns, rows

        @staticmethod
        def terminal_size():
            """Get the width and height of the terminal.
            http://code.activestate.com/recipes/440694-determine-size-of-console-window-on-windows/
            http://stackoverflow.com/questions/17993814/why-the-irrelevant-code-made-a-difference
            :return: Width (number of characters) and height (number of lines) of the terminal.
            :rtype: tuple
            """
            try:
                return WINAPI._terminal_size(WINAPI._GetStdHandle(WINAPI._STDOUT))
            except OSError:
                try:
                    return WINAPI._terminal_size(WINAPI._GetStdHandle(WINAPI._STDERR))
                except OSError:
                    return _DEFAULT_WIDTH, _DEFAULT_HEIGHT
        
        @staticmethod
        def try_enable_ansi():
            """Try enabling ANSI colors
            https://stackoverflow.com/questions/44482505/setconsolemode-returning-false-when-enabling-ansi-color-under-windows-10"""
            lpMode = wintypes.DWORD()
            handle = WINAPI._GetStdHandle(WINAPI._STDOUT)
            if WINAPI._GetConsoleMode(handle, ctypes.byref(lpMode)):
               
                if not WINAPI._SetConsoleMode(handle, lpMode.value | WINAPI._ENABLE_VIRTUAL_TERMINAL_PROCESSING):
                    return False
            else:
                return False
            
            lpMode = wintypes.DWORD()
            handle = WINAPI._GetStdHandle(WINAPI._STDERR)
            if WINAPI._GetConsoleMode(handle, ctypes.byref(lpMode)):
                if not WINAPI._SetConsoleMode(handle, lpMode.value | WINAPI._ENABLE_VIRTUAL_TERMINAL_PROCESSING):
                    return False
            else:
                return False
            
            return True

        @staticmethod
        @lru_cache()
        def get_font():
            handle = WINAPI._GetStdHandle(WINAPI._STDOUT)
            font = CONSOLE_FONT_INFOEX()
            font.cbSize = sizeof(CONSOLE_FONT_INFOEX)
            if not WINAPI._GetCurrentConsoleFontEx(handle, False, byref(font)):
                return None
            else:
                return font.FaceName

    NIXAPI = None
else:
    WINAPI = None
    class NIXAPI:

        @staticmethod
        def terminal_size():
            try:
                device = __import__('fcntl').ioctl(0, __import__('termios').TIOCGWINSZ, '\0\0\0\0\0\0\0\0')
            except IOError:
                return _DEFAULT_WIDTH, _DEFAULT_HEIGHT
            height, width = struct.unpack('hhhh', device)[:2]
            return width, height

class Terminal:
    
    @lru_cache()
    def is_tty(self):
        return sys.stdout.isatty()

    @lru_cache()
    def is_cmd_exe(self):
        if WINAPI:
            return WINAPI.get_ppname() == "cmd.exe" and WINAPI.winapi_test()
        else:
            return False
        
    @lru_cache()
    def is_powershell(self):
        if WINAPI:
            return WINAPI.get_ppname() == "powershell.exe" and WINAPI.winapi_test()
        else:
            return False
    
    @lru_cache()
    def supports_ansi_escapes(self):
        """Return True if the terminal supports ANSI escape sequences.
        https://unix.stackexchange.com/questions/23763/checking-how-many-colors-my-terminal-emulator-supports
        https://stackoverflow.com/questions/4842424/list-of-ansi-color-escape-sequences
        """
        if not sys.stdout.isatty():
            return False
        elif WINAPI:
            if WINAPI.winapi_test():
                return WINAPI.try_enable_ansi()
            else:
                return True
        else:
            return True
    
    
        if WINAPI:
            return WINAPI.terminal_size()
        else:
            return NIXAPI.terminal_size()

TERMINAL = Terminal()

class Table:

    def __init__(self, data, style='default', separate='header', terminal=TERMINAL, pad=1, left_align=set()):
        assert separate in ('header', 'row', 'none')
        assert style in ('default', 'ascii', 'no-round')
        self.style = style
        self.separate = separate
        self.pad = pad

        max_data = max(map(len, data))
       
        for row in data:
            if len(row) < max_data:
                row.extend([""] * (max_data - len(row)))
        self._original_data = deepcopy(data)
        
        self.data = data
        
        for ix in range(max_data):
            
            col_size = max(map(lambda r: len(str(r[ix])), self.data))
            for j, row in enumerate(self.data) or ix in left_align:
                if j == 0 or ix in left_align:
                    row[ix] = str(" " * pad) + str(row[ix]).ljust(col_size) + str(" " * pad)
                else:
                    row[ix] = str(" " * pad) + str(row[ix]).rjust(col_size) + str(" " * pad)
        self.terminal = terminal
        self.left_align = left_align
            
    def __str__(self):
        return self.getvalue(fit=False)

    def getvalue(self, fit=True):

        buffer = io.StringIO()
        if len(self.data) >= 1:
            first_draw_bottom = len(self.data) == 1 or self.separate in ('header', 'row')
            self._print_row(self.data[0], buffer, draw_top=True, draw_bottom=first_draw_bottom, is_first=True, 
                            is_last=len(self.data) == 1, is_connected=len(self.data) != 1)
            first_line = buffer.getvalue().splitlines()[0]

            if len(first_line) > self.terminal.terminal_size()[0] and len(self._original_data[0]) > 1:
                data_ = [d[:-1] for d in self._original_data]
                table = Table(data_, style=self.style, separate=self.separate, terminal=self.terminal, pad=self.pad, left_align=self.left_align)
                return table.getvalue(fit)

            for row in self.data[1:-1]:
                self._print_row(row, buffer, draw_top=False, draw_bottom=self.separate == 'row', is_first=False, 
                                is_last=False, is_connected=self.separate == 'row')
            if len(self.data) > 1:
                self._print_row(self.data[-1], buffer, draw_top=False, draw_bottom=True, is_first=False, 
                                is_last=True, is_connected=False)
        
        if self.style == 'default':
            res = buffer.getvalue()
        elif self.style == 'no-round':
            res = buffer.getvalue()
            res = res.replace("╭", '┌')
            res = res.replace("╮", '┐')
            res = res.replace("╰", '└')
            res = res.replace("╯", "┘")
        elif self.style == 'ascii':
            res = buffer.getvalue()
            res = res.replace("╭", '+')
            res = res.replace("╮", '+')
            res = res.replace("╰", '+')
            res = res.replace("╯", "+")
            res = res.replace("├", "+")
            res = res.replace("┬", "+")
            res = res.replace("┤", "+")
            res = res.replace("┼", "+")
            res = res.replace("┴", "+")
            res = res.replace("─", "-")
            res = res.replace("│", "|")
            
        return res

    def _print_row(self, row, file, draw_top, draw_bottom, is_first, is_last, is_connected):
        
        if draw_top:
            file.write("╭" if is_first else "├")
            for col in row[:-1]:
                file.write(str("─" * len(col)))
                file.write("┬")
            file.write(str("─" * len(row[-1])))
            file.write("╮")
            file.write("\n")
        
        file.write("│")
        for col in row:
            file.write(col)
            file.write("│")
        file.write("\n")

        if draw_bottom:
            file.write("╰" if is_last else "├")
            for col in row[:-1]:
                file.write(str("─" * len(col)))
                file.write("┼" if is_connected else "┴")
            file.write(str("─" * len(row[-1])))
            file.write("┤" if is_connected else "╯")
            if not is_last:
                file.write("\n")

class StatsTable:

    def __init__(self, conf, width=70, pad=4, left_align=set()):
        self.conf = conf
        self.data = {}
        self.width = width
        self.pad = pad
        self.left_align = left_align

        self.by_cat = {}
        self.cats = []
        self.titles = []

        for item in self.conf:
            self.by_cat.setdefault(item['category'], {})

            if not item['category'] in self.cats:
                self.cats.append(item['category'])

            if not item['title'] in self.titles:
                self.titles.append(item['title'])
            
            self.by_cat[item['category']][item['title']] = (item['name'], item['format'])
    
    def update(self, data):
        for k,v in data.items():
            self.data[k] = v
    
    def __str__(self):
        return self.getvalue()
        
    def getvalue(self):
        
        title_row = [""]
        title_row.extend(self.titles)
        cat_rows = []
       

        for cat in self.cats:
            row = [cat]
            for title in self.titles:
                name, fmt = self.by_cat[cat][title]
                if name in self.data:
                    value = self.data[name]
                    fmt = "{:" +  fmt.lstrip("{").rstrip("}").lstrip(":") + "}"
                    row.append(fmt.format(value))
                else:
                    row.append("-")
            cat_rows.append(row)
        
        data = [title_row] + cat_rows
      
        t = Table(data, left_align=self.left_align)
        return t.getvalue(fit=False) + "\n"

class Display:

    def __init__(self,
                 highlight_color=36,
                 table_style='default',
                 progress_style='default', 
                 is_interactive=True,
                 stdout=sys.stdout, 
                 stderr=sys.stderr):
        self.stdout = stdout
        self.stderr = stderr
        self.highlight_color = highlight_color
        self.table_style = table_style
        self.progress_style = progress_style
        self.is_interactive = is_interactive
        self.cursor_hidden = False
        self.quiet = False
    
    def table(self, data, style=None, separate='header', terminal=TERMINAL, pad=1, left_align=set()):
        if not style:
            style = self.table_style
        return Table(data=data, style=style, separate=separate, terminal=terminal, pad=pad, left_align=left_align)
    
    def stats_table(self, conf, width=70, pad=4, left_align=set()):
        return StatsTable(conf=conf, width=width, pad=pad, left_align=left_align)
    
    def progressbar(self,
                    iterable=None,
                    steps=None,
                    title=None,
                    epochs=None,
                    style=None,
                    label="it",
                    file=sys.stdout,
                    width=70,
                    color=None,
                    keep=True,
                    show=None,
                    post=None):
        if style is None:
            style = self.progress_style
        
        if color is None:
            color = self.highlight_color
        
        if show is None:
            show = self.is_interactive
        
        return ProgressBar(iterable,
                           steps=steps,
                           title=title,
                           epochs=epochs,
                           style=style,
                           label=label,
                           file=self.stdout,
                           width=width,
                           color=color,
                           keep=keep,
                           show=show,
                           post=post)
    
    def training_feedback(self, stats, steps=None, display_progress='epochs-steps', epochs=None):

        return TrainingFeedback(stats=stats, 
                                steps=steps, 
                                display_progress=display_progress,
                                epochs=epochs,
                                display=self,
                                show=self.is_interactive)

    def print(self, *args):
        if not self.quiet:
            print(*args, file=self.stdout)
    
    def write(self, string):
        if not self.quiet:
            self.stdout.write(string)
    
    def hide_cursor(self):
        if self.is_interactive and not self.cursor_hidden:
            self.cursor_hidden = True
            self.stdout.write("\033[?25l")
            self.stdout.flush()

    def unhide_cursor(self):
        if self.is_interactive and self.cursor_hidden:
            self.cursor_hidden = False
            self.stdout.write("\033[?25h")
            self.stdout.flush()
    
    def cleanup(self):
        if self.cursor_hidden:
            self.unhide_cursor()


_highlight_color=36
_table_style='default'
_progress_style='default'
_is_interactive=True

if TERMINAL.is_tty() and TERMINAL.supports_ansi_escapes():
    if TERMINAL.supports_ansi_escapes():
        if WINAPI:
            font = WINAPI.get_font()
            if font == 'Consolas' or font == 'Lucida Console':
                _progress_style = 'consolas'
            if font == 'Lucida Console':
                _table_style = 'no-round'
else:
    _highlight_color=None
    _table_style='ascii'
    _progress_style='ascii'
    _is_interactive=False

DISPLAY = Display(highlight_color=_highlight_color,
                  table_style=_table_style,
                  progress_style=_progress_style, 
                  is_interactive=_is_interactive)


class TrainingFeedback:

    def __init__(self, epochs=None, steps=None, display_progress='epochs-steps', stats=[], show=True, display=DISPLAY):
        assert display_progress in ('epochs', 'steps', 'epochs-steps')

        self.steps = steps
        self.stats = stats
        self.epochs = epochs
        self.display_progress = display_progress
        self.stats_table = None
        self.progress_bar = None
        self.stats_table_height = None
        self.did_start = False
        self.display = display
        self.steps_timing = []
        self.show = show

    def start(self):
        if self.did_start:
            return
        
        self.display.hide_cursor()

        self.did_start = True
        
        self.stats_table = self.display.stats_table(self.stats, left_align=set([0]))
        if self.display_progress == 'epochs-steps':
            label = "steps"
        else:
            label = self.display_progress

        self.progress_bar = self.display.progressbar(
            iterable=None,
            steps=self.steps if self.display_progress != 'epochs' else self.epochs,
            epochs=self.epochs,
            label=label,
            show=self.show
        )

        stats_table_str = self.stats_table.getvalue()
        self.stats_table_height = len(stats_table_str.splitlines())
        if self.show:
            self.display.write(stats_table_str)
            self.display.print("")
        
        self.progress_bar.start()
    
    def update(self, epoch=None, step=None, **stats):
        assert self.did_start, "must call start() first"

        if self.display_progress == 'epochs-steps':
            self.steps_timing.append(time.time())
            if len(self.steps_timing) >= 5:
                self.steps_timing = self.steps_timing[-5:]
                intervals = list(map(lambda t: t[1] - t[0], zip(self.steps_timing[:-1], self.steps_timing[1:])))
                avg_intv = sum(intervals) / len(intervals)

				
                if self.steps * avg_intv <= 1.5:
                    self.display_progress = 'epochs'

                    self.progress_bar = self.display.progressbar(
                        iterable=None,
                        steps=self.epochs * self.steps,
                        epochs=self.epochs,
                        label="steps",
                        show=self.show
                    )
                    self.progress_bar.start()

        self.stats_table.update(stats)
        if self.show:
            self.display.stdout.write("\r")
            self.display.stdout.write("\033[" + str(self.stats_table_height + 1) + "A")
            self.display.write(self.stats_table.getvalue())
            self.display.print("")

        if self.display_progress == 'epochs-steps':
            if step is not None and epoch is not None and epoch < self.epochs and step != self.steps * self.epochs:
                self.progress_bar.update(epoch=epoch, step=step % self.steps)
        elif self.display_progress == 'epochs':
            if step is not None and epoch is not None:
                self.progress_bar.update(epoch=epoch, step=step)
        elif self.display_progress == 'steps':
            if step is not None:
                self.progress_bar.update(epoch=None, step=step)
        
    
    def stop(self):
        self.progress_bar.stop()
self.display.unhide_cursor()
