#!/usr/bin/env python

#########################################
# Imports
#########################################
import os

# - Logging
import logging

# - Multithreading
from twisted.internet import reactor

# - Modbus
from pymodbus.server.asynchronous import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.transaction import ModbusRtuFramer, ModbusAsciiFramer

# - World Simulator
import sys, random
import pygame
from pygame.locals import *
from pygame.color import *
import pymunk.pygame_util
import pymunk

import pprint

SCREEN_WIDTH = 1824
SCREEN_HEIGHT = 984
FPS=60.0

FACTORY_POSX = 620 #615 #100 #540
FACTORY_POSY = 90 # 100 #325
FACTORY_WIDTH = 600
FACTORY_HEIGHT = 350

MODBUS_SERVER_PORT=502

PLC_TAG_LEVEL_SENSOR = 0x1
PLC_TAG_LIMIT_SWITCH = 0x2
PLC_TAG_MOTOR = 0x3
PLC_TAG_NOZZLE = 0x4
PLC_TAG_RUN = 0x10
PLC_TAG_RESET = 0x9
PLC_REG_NUM_BOTTLES_OK = 0x5
PLC_REG_NUM_BOTTLES_KO = 0x6
PLC_REG_RELAY = 0x7
PLC_REG_PRESSURE = 0xb
PLC_REG_STATUS = 0x32

# Global Variables
global bottles
bottles = []
global num_bottles
num_bottles = 0
global num_bottles_ko
num_bottles_ko = 0
global num_bottles_txt_position_x
global num_bottles_txt_position_y
global pressure_value
pressure_value = 200


PYGAME_REALIGN_Y = SCREEN_HEIGHT - FACTORY_POSY


#########################################
# Util Functions
#########################################
def get_ip_address():
    ifs = []
    all_ifs = os.popen('ifconfig -a | sed \'s/[ \t].*//;/^\(lo\|\)$/d\'')
    ifs_data = all_ifs.read()
    if_data_array = ifs_data.split("\n")
    for interf in if_data_array:
        if len(interf) > 0:
            #pprint.pprint(interf)
            f = os.popen('ifconfig ' + interf + ' | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
            ifs.append(f.read()[:-1])
            f.close()
    return ifs

def PLCSetTag(addr, value):
    context[0x0].setValues(3, addr, [value])

def PLCGetTag(addr):
    return context[0x0].getValues(3, addr, count=1)[0]

def PLCGetRegister(addr):
    value = context[0x0].getValues(3, addr, count=1)[0]
    return value

def PLCSetRegister(addr, value):
    context[0x0].setValues(3, addr, [value])

def factory_position(x, y):
    return (FACTORY_POSX + x, FACTORY_POSY + y)

def pygame_factory_position(x, y):
    return (int(x), PYGAME_REALIGN_Y  - int(y))


tmp_x, tmp_y = factory_position(FACTORY_WIDTH - 60, 130)
num_bottles_txt_position_x, num_bottles_txt_position_y = pygame_factory_position(tmp_x, tmp_y)

def draw_ball(screen, ball, color=THECOLORS['blue'], width=2):
    o = pymunk.Vec2d(ball.body.position.x + ball.offset.x,
                     ball.body.position.y + ball.offset.y)
    pygame.draw.circle(screen, color, pygame_factory_position(o.x, o.y), int(ball.radius), width)

def draw_poly(screen, poly, color=THECOLORS['dodgerblue4']):
    points = poly.get_vertices()
#    pprint.pprint(points)
    fpoints = []
    for p in points:
        tmp_x,tmp_y = factory_position(p.x, p.y)
        fpoints.append(pygame_factory_position(tmp_x, tmp_y))
    pygame.draw.polygon(screen, color, fpoints)


def draw_line(screen, line, color=THECOLORS['dodgerblue4'], width=1):
    o = [line.body.position + line.a.rotated(line.body.angle),
         line.body.position + line.b.rotated(line.body.angle)]

    start = pygame_factory_position(o[0].x, o[0].y)
    end = pygame_factory_position(o[1].x, o[1].y)
    pygame.draw.line(screen, color, start, end, width)

def draw_lines(screen, lines, color=THECOLORS['dodgerblue4']):
    for line in lines:
        draw_line(screen, line, color, int(line.radius))

def draw_screen(screen, s):
    for obj in s:
        if type(obj) == pymunk.shapes.Segment:
            line = obj
            draw_line(screen, line, THECOLORS['black'], int(line.radius))
        elif type(obj) == pymunk.shapes.Poly:
            poly = obj
            v = poly.get_vertices()
            if v[0].x == FACTORY_WIDTH - 92:
                draw_poly(screen, poly, pygame.Color(0,255,255,0))
            else:
                draw_poly(screen, poly, THECOLORS['white'])

def draw_beacon(screen, beacon, color):
    draw_poly(screen, beacon, color)

def draw_base(screen, base):
    for obj in base:
        if type(obj) == pymunk.shapes.Circle:
            ball = obj
            draw_ball(screen, ball, THECOLORS['black'])
        elif type(obj) == pymunk.shapes.Segment:
            line = obj
            draw_line(screen, line, THECOLORS['black'], int(line.radius))
        elif type(obj) == pymunk.shapes.Poly:
            poly = obj
            color = pygame.Color(76,116,135,0)
            draw_poly(screen, poly, color)


def bottle_in_place(arbiter, space, data):
    PLCSetTag(PLC_TAG_LIMIT_SWITCH, 1) 
    PLCSetTag(PLC_TAG_LEVEL_SENSOR, 0)
    PLCSetTag(PLC_TAG_NOZZLE, 1) # Open nozzle
    return False

def level_ok(arbiter, space, data):
    PLCSetTag(PLC_TAG_LIMIT_SWITCH, 0) # Limit Switch Release, Fill Bottle
    PLCSetTag(PLC_TAG_LEVEL_SENSOR, 1) # Level Sensor Hit, Bottle Filled
    PLCSetTag(PLC_TAG_NOZZLE, 0) # Close nozzle
    return False

def no_collision(arbiter, space, data):
    return False

def collision(arbiter, space, data):
    return True

def add_new_bottle(arbiter, space, data):
    global bottles
    bottles.append(add_bottle(space))
    return False

def add_bottle_in_sensor(space):
    body = pymunk.Body(body_type=pymunk.Body.STATIC)
    body.position = factory_position(0, 0)

    radius = 4
    shape = pymunk.Circle(body, radius, (110, 25))
    shape.collision_type = 0x7 # 'bottle_in'
    space.add(shape)
    return shape

def add_level_sensor(space):
    body = pymunk.Body(body_type=pymunk.Body.STATIC)
    body.position = factory_position(0, 0)
    radius = 3
    shape = pymunk.Circle(body, radius, (135, 100))
    shape.collision_type = 0x4 # level_sensor
    space.add(shape)
    return shape

def add_limit_switch(space):
    body = pymunk.Body(body_type=pymunk.Body.STATIC)
    body.position = factory_position(0, 0)
    radius = 3
    shape = pymunk.Circle(body, radius, (180, 25))
    shape.collision_type = 0x1 # switch
    space.add(shape)
    return shape

def add_screen(space):
    base = []

    body = pymunk.Body(body_type=pymunk.Body.STATIC)
    body.position = factory_position(0, 0)

    vertices = [[FACTORY_WIDTH - 96, 100], [FACTORY_WIDTH - 2, 100], [FACTORY_WIDTH - 2, 135], [FACTORY_WIDTH - 96, 135]]
    s = pymunk.Poly(body, vertices, radius=1.0)
    base.append(s)
    vertices = [[FACTORY_WIDTH - 92, 102], [FACTORY_WIDTH - 4, 102], [FACTORY_WIDTH - 4, 133], [FACTORY_WIDTH - 92, 133]]
    s = pymunk.Poly(body, vertices, radius=1.0)
    base.append(s)

    top = pymunk.Segment(body, (FACTORY_WIDTH - 94, 133), (FACTORY_WIDTH - 4, 133), 1.0)
    left = pymunk.Segment(body, (FACTORY_WIDTH - 94, 133), (FACTORY_WIDTH - 94, 102), 1.0)
    right = pymunk.Segment(body, (FACTORY_WIDTH - 4, 133), (FACTORY_WIDTH - 4, 102), 1.0)
    bottom = pymunk.Segment(body, (FACTORY_WIDTH - 94, 102), (FACTORY_WIDTH - 4, 102), 1.0)
    base.append(top)
    base.append(left)
    base.append(bottom)
    base.append(right)


    return base

def add_beacon(space):

    body = pymunk.Body(body_type=pymunk.Body.STATIC)
    body.position = factory_position(0, 0)

    #beacon_top = pymunk.Segment(body, (FACTORY_WIDTH - 60, 200), (FACTORY_WIDTH - 40, 200), 3.0)
    #beacon_left = pymunk.Segment(body, (FACTORY_WIDTH - 60, 200), (FACTORY_WIDTH - 60, 175), 3.0)
    #beacon_right = pymunk.Segment(body, (FACTORY_WIDTH - 40, 200), (FACTORY_WIDTH - 40, 175), 3.0)

    #vertices = [[FACTORY_WIDTH - 58, 233 * FACTORY_HEIGHT / 1920],
    #            [FACTORY_WIDTH - 42, 233 * FACTORY_HEIGHT / 1920],
    #            [FACTORY_WIDTH - 42, 211 * FACTORY_HEIGHT / 1920],
    #            [FACTORY_WIDTH - 58, 211 * FACTORY_HEIGHT / 1920]]
    vertices = [[FACTORY_WIDTH - 58, 233],
                [FACTORY_WIDTH - 42, 233],
                [FACTORY_WIDTH - 42, 211],
                [FACTORY_WIDTH - 58, 211]]
    beacon = pymunk.Poly(body, vertices, radius=1.0)

    return beacon


def add_base(space):
    global FACTORY_POSX
    global FACTORY_POSY
    global SCREEN_WIDTH
    global SCREEN_HEIGHT
    global PYGAME_REALIGN_Y
    radius = 10
    inner_radius = 7
    base = []
    num = 6

    body = pymunk.Body(body_type=pymunk.Body.STATIC)
    body.position = factory_position(0, 0)

    top = pymunk.Segment(body, (0, 20), (FACTORY_WIDTH, 20), 2.0)
    inner_top = pymunk.Segment(body, (0, 15), (FACTORY_WIDTH, 15), 1.0)
    bottom = pymunk.Segment(body,(0, 0), (FACTORY_WIDTH, 0), 2.0)
    inner_bottom = pymunk.Segment(body, (0, 5), (FACTORY_WIDTH, 5), 1.0)

    top.collision_type = 0x6 # top base
    top.friction = 0.5
    #space.add(top, inner_top, bottom, inner_bottom)
    space.add(top)

    base.append(top)
    base.append(inner_top)
    base.append(bottom)
    base.append(inner_bottom)

    for i in range(1, num + 1):
        posx = (i * (FACTORY_WIDTH / (num))) - 20

        wheel = pymunk.Circle(body, radius, (posx, 10))
        inner_wheel = pymunk.Circle(body, inner_radius, (posx, 10))
        space.add(wheel, inner_wheel)
        base.append(wheel)
        base.append(inner_wheel)

    vertices = [[FACTORY_WIDTH - 100, 20], [FACTORY_WIDTH - 100, 188], [FACTORY_WIDTH - 75, 210], [FACTORY_WIDTH - 25, 210], [FACTORY_WIDTH, 188], [FACTORY_WIDTH, 20]]
    casing = pymunk.Poly(body, vertices, radius=1.0)
    base.append(casing)

    #vertices = [[0, 305.5], [160, 305.5], [160, 297.5], [0, 297.5]]
    #vertices = [[0, 305.5 * SCREEN_HEIGHT / 984], [160, 305.5 * SCREEN_HEIGHT / 984], [160, 297.5 * SCREEN_HEIGHT / 984], [0, 297.5 * SCREEN_HEIGHT / 984]]
    vertices = [[-1, 309.5 * SCREEN_HEIGHT / 984], [160, 309.5 * SCREEN_HEIGHT / 984], [160, 302 * SCREEN_HEIGHT / 984], [-1, 302 * SCREEN_HEIGHT / 984]]
    #pprint.pprint(SCREEN_HEIGHT)
    #pprint.pprint(vertices)
    #vertices = [[0, 305.5], [160, 305.5], [160, 297.5], [0, 297.5], [0, 305.5]]
    #vertices = [[0, 238], [160, 238], [160, 230], [0, 230]]
    pipe = pymunk.Poly(body, vertices, radius=1.0)
    space.add(pipe)
    base.append(pipe)
    vertices = [[160, 309.5 * SCREEN_HEIGHT / 984], [160, 155], [150, 155], [150, 309.5 * SCREEN_HEIGHT / 984]]
    pipe = pymunk.Poly(body, vertices, radius=1.0)
    space.add(pipe)
    base.append(pipe)

    beacon_top = pymunk.Segment(body, (FACTORY_WIDTH - 60, 235), (FACTORY_WIDTH - 40, 235), 3.0)
    beacon_left = pymunk.Segment(body, (FACTORY_WIDTH - 60, 235), (FACTORY_WIDTH - 60, 210), 3.0)
    beacon_right = pymunk.Segment(body, (FACTORY_WIDTH - 40, 235), (FACTORY_WIDTH - 40, 210), 3.0)
    base.append(beacon_top)
    base.append(beacon_left)
    base.append(beacon_right)

    return (base)


class my_rand():
    def __init__(self, minimum, maximum):
        self.count = minimum
        self.minimum = minimum
        self.maximum = maximum
    
    def randint(self):
        self.count += 1

        if self.count < self.minimum or self.count > self.maximum:
            self.count = self.minimum

        return self.count
        
#global randball
#randball = my_rand(154, 154)
global randrun
randrun = my_rand(1, 10)

def add_ball(space):
    #global randball
    #x = random.randint(1, 100)
    #if x < 80:
    mass = 1
    #else:
    #    mass = 0.01
    radius = 3
    inertia = pymunk.moment_for_circle(mass, 0, radius, (0,0))
    body = pymunk.Body(mass, inertia)
    #x = random.randint(154,155)
    #x = randball.randint() #_my_rand(154, 155)
    #pprint.pprint(x)
    body.position = factory_position(154, 150)
    shape = pymunk.Circle(body, radius, (0,0))
    shape.collision_type = 0x5 #liquid
    space.add(body, shape)
    return shape


def add_bottle(space):
    mass = 20000
    inertia = 0
    #b = pymunk.Body(mass, inertia)
    #b = pymunk.Body(mass, inertia, body_type=pymunk.Body.DYNAMIC)
    b = pymunk.Body()
    b.position = factory_position(0, 26)

    #pprint.pprint("!!!! ADD BOTTLE !!!!")

    l1 = pymunk.Segment(b, (0,0), (53,0), 6)
    l2 = pymunk.Segment(b, (1,0), (1, 80), 4)
    l3 = pymunk.Segment(b, (51,0), (51,80), 4)
    l4 = pymunk.Segment(b, (1,80), (11,90), 4)
    l5 = pymunk.Segment(b, (51,80), (41,90), 4)
    l6 = pymunk.Segment(b, (11,90), (11,110), 4)
    l7 = pymunk.Segment(b, (41,90), (41,110), 4)

    l1.friction = 0.94
    l2.friction = 0.94
    l3.friction = 0.94
    l4.friction = 0.94
    l5.friction = 0.94
    l6.friction = 0.94
    l7.friction = 0.94

    l1.density = 200 * l1.radius
    l2.density = 200 * l2.radius
    l3.density = 200 * l3.radius
    l4.density = 200 * l4.radius
    l5.density = 200 * l5.radius
    l6.density = 200 * l6.radius
    l7.density = 200 * l7.radius

    #l1.mass = 200 * l1.radius
    #l2.mass = 200 * l2.radius
    #l3.mass = 200 * l3.radius
    #l4.mass = 200 * l4.radius
    #l5.mass = 200 * l5.radius
    #l6.mass = 200 * l6.radius
    #l7.mass = 200 * l7.radius

    l1.collision_type = 0x2 # bottle_bottom
    l2.collision_type = 0x3 # bottle_side
    l3.collision_type = 0x3 # bottle_side
    l4.collision_type = 0x11 # bottle_side
    l5.collision_type = 0x11 # bottle_side
    l6.collision_type = 0x11 # bottle_side
    l7.collision_type = 0x11 # bottle_side

    space.add(b, l1, l2, l3, l4, l5, l6, l7)
    return l1, l2, l3, l4, l5, l6, l7

def runWorld():
    global num_bottles
    global num_bottles_ko
    global num_bottles_txt_position_x
    global num_bottles_txt_position_y
    global bottles
    global randrun
    global pressure_value
    global FACTORY_POSX
    global FACTORY_POSY
    global SCREEN_WIDTH
    global SCREEN_HEIGHT
    global PYGAME_REALIGN_Y

    pygame.init()
    pygame_info = pygame.display.Info()
    FACTORY_POSX = 620 * pygame_info.current_w / SCREEN_WIDTH#615 #100 #540
    FACTORY_POSY = 90 * pygame_info.current_h / SCREEN_HEIGHT # 100 #325
    SCREEN_WIDTH = pygame_info.current_w
    SCREEN_HEIGHT = pygame_info.current_h
    PYGAME_REALIGN_Y = SCREEN_HEIGHT - FACTORY_POSY

    #set status to 1
    PLCSetRegister(PLC_REG_STATUS,1)

    screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT),pygame.RESIZABLE)
    pygame.display.set_caption("Bottle-Filling Factory - World View - VirtuaPlant")
    bg = pygame.image.load("/home/pi/Desktop/pi/Factory_bkg.png")
    bg = pygame.transform.scale(bg, (SCREEN_WIDTH, SCREEN_HEIGHT))
    
    clock = pygame.time.Clock()
    running = True

    space = pymunk.Space()
    space.gravity = (0, -1200)

    c = space.add_collision_handler(0x1, 0x2)
    c.begin = bottle_in_place 
    c = space.add_collision_handler(0x4, 0x5)
    c.begin = level_ok
    c = space.add_collision_handler(0x4, 0x6)
    c.begin = no_collision
    c = space.add_collision_handler(0x1, 0x6)
    c.begin = no_collision
    c = space.add_collision_handler(0x1, 0x3)
    c.begin = no_collision
    c = space.add_collision_handler(0x4, 0x3)
    c.begin = no_collision
    c = space.add_collision_handler(0x7, 0x2)
    c.separate = add_new_bottle
    c.begin = no_collision
    c = space.add_collision_handler(0x7, 0x3)
    c.begin = no_collision
    #c = space.add_collision_handler(0x5, 0x3)
    #c.begin = collision

    base = add_base(space)
    s = add_screen(space)
    beacon = add_beacon(space)
    #nozzle = add_nozzle(space)
    limit_switch = add_limit_switch(space)
    level_sensor = add_level_sensor(space)
    bottle_in = add_bottle_in_sensor(space)

    bottles.append(add_bottle(space))

    balls = []
    ticks_to_next_ball = 1

    modifiable_rect = screen.get_rect(top=SCREEN_HEIGHT-FACTORY_HEIGHT-FACTORY_POSY,
                                      left=FACTORY_POSX - 1, width=FACTORY_WIDTH, height=FACTORY_HEIGHT)
    #screen.fill(THECOLORS["white"], rect=modifiable_rect)
    screen.fill(THECOLORS["white"])
    #options = pymunk.pygame_util.DrawOptions(screen)
    #space.debug_draw(options)

    draw_base(screen, base)
    draw_screen(screen, s)

    fontBig = pygame.font.SysFont(None, 40)
    fontMedium = pygame.font.SysFont(None, 26)
    fontSmall = pygame.font.SysFont(None, 18)
    title = fontMedium.render(str("Bottle-filling factory"), 1, THECOLORS['deepskyblue'])
    name = fontBig.render(str("VirtuaPlant"), 1, THECOLORS['gray20'])
    instructions = fontSmall.render(str("(press ESC to quit)"), 1, THECOLORS['gray'])
    #ips = get_ip_address()
    import socket
    try:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _sock.connect(("8.8.8.8", 80))
        real_ip = _sock.getsockname()[0]
        _sock.close()
    except:
        real_ip = "0.0.0.0"
    ip_addr = fontSmall.render(real_ip, 1, THECOLORS['gray'])
    screen.blit(title, (10, 40))
    screen.blit(name, (10, 10))
    screen.blit(instructions, (SCREEN_WIDTH-115, 10))
    screen.blit(ip_addr, (SCREEN_WIDTH-100, 50))
    #set default pressure value
    PLCSetRegister(PLC_REG_PRESSURE,pressure_value)

    #pprint.pprint(num_bottles_txt_position_x)
    #pprint.pprint(num_bottles_txt_position_y)

    beacon_color = THECOLORS['white']
    screen.blit(bg, (0, 0))
    while running:
        clock.tick(FPS)

        for event in pygame.event.get():
            if event.type == QUIT:
                running = False
            elif event.type == KEYDOWN and event.key == K_ESCAPE:
                running = False

        screen.fill(THECOLORS["white"], rect=modifiable_rect)
        #screen.fill(THECOLORS["white"])
        
        #print("RE="+str(PLCGetTag(PLC_TAG_RESET))+" RU="+str(PLCGetTag(PLC_TAG_RUN))+"\n")

        if PLCGetTag(PLC_TAG_RESET):
            PLCSetTag(PLC_TAG_LIMIT_SWITCH, 0)
            PLCSetTag(PLC_TAG_LEVEL_SENSOR, 0)
            PLCSetTag(PLC_TAG_NOZZLE, 0)
            PLCSetTag(PLC_TAG_MOTOR, 1)
            PLCSetTag(PLC_TAG_RUN, 1)
            PLCSetRegister(PLC_REG_NUM_BOTTLES_OK, 0)
            PLCSetRegister(PLC_REG_NUM_BOTTLES_KO, 0)
            PLCSetRegister(PLC_REG_RELAY, 0)
            PLCSetRegister(PLC_REG_PRESSURE, 200)
            num_bottles = 0
            num_bottles_ko = 0
            pressure_value = 200
            PLCSetTag(PLC_TAG_RESET, 0)

        if PLCGetTag(PLC_TAG_RUN):
            # Motor Logic
            if (PLCGetTag(PLC_TAG_LIMIT_SWITCH) == 1):
                PLCSetTag(PLC_TAG_MOTOR, 0)
                
            if (PLCGetTag(PLC_TAG_LEVEL_SENSOR) == 1):
                PLCSetTag(PLC_TAG_MOTOR, 1)
                    
            ticks_to_next_ball -= 1
                
            if not PLCGetTag(PLC_TAG_LIMIT_SWITCH):
                PLCSetTag(PLC_TAG_MOTOR, 1)

            if ticks_to_next_ball <= 0 and PLCGetTag(PLC_TAG_NOZZLE):
                ticks_to_next_ball = 1
                ball_shape = add_ball(space)
                balls.append(ball_shape)

            # Move the bottles
            if PLCGetTag(PLC_TAG_MOTOR) == 1:
                #added pressure login on ok-ko
		#pressure_value = 60
		#PLCSetRegister(PLC_REG_PRESSURE, pressure_value)
                for bottle in bottles:
                    #speed = 2.5
                    #bottle[0].body.position += pymunk.Vec2d(1,0) * speed
                    bottle[0].surface_velocity = (-100, 0)
                    
            else:
                #added pressure login on ok-ko
		#pressure_value = 30
		#PLCSetRegister(PLC_REG_PRESSURE, pressure_value)
                for bottle in bottles:
                    bottle[0].surface_velocity = (0, 0)

        else:
            PLCSetTag(PLC_TAG_MOTOR, 0)
            for bottle in bottles:
                bottle[0].surface_velocity = (0, 0)

        for ball in balls:
            if ball.body.position.x > (525 + FACTORY_POSX) or (ball.body.position.y - 2) < FACTORY_POSY or (ball.body.position.x - 2) < FACTORY_POSX:
                space.remove(ball, ball.body)
                balls.remove(ball)
                continue
            #pprint.pprint(ball.body.moment)
            #if ball.body.moment == 4.5:
            color = pygame.Color(255,228,76,0)
            draw_ball(screen, ball, color)
            #else:
            #    color = pygame.Color(255,246,206,0)
            #    draw_ball(screen, ball, color)
                

        # Draw bottles
        for bottle in bottles:
            #pprint.pprint(bottle[0].body.position)
            if bottle[0].body.position.x > (FACTORY_POSX + 510):
                space.remove(bottle, bottle[0].body)
                bottles.remove(bottle)
                #x = random.randint(1, 100)
                x = randrun.randint()#my_rand(1, 10)
                if x <= 7:
                    num_bottles += 1
                    if num_bottles > 65535:
                        num_bottles = 0
                    PLCSetRegister(PLC_REG_NUM_BOTTLES_OK, num_bottles)
                    beacon_color = THECOLORS['green']
                    #turn off relay - write on register value 0
		    pressure_value = 200
                    PLCSetRegister(PLC_REG_RELAY, 0)
		    PLCSetRegister(PLC_REG_PRESSURE, pressure_value)

                else:
                    num_bottles_ko += 1
                    if num_bottles_ko > 65535:
                        num_bottles_ko = 0
                    beacon_color = THECOLORS['red']
                    PLCSetRegister(PLC_REG_NUM_BOTTLES_KO, num_bottles_ko)
                    #turn off relay - write on register value 1
                    pressure_value = 600
     		    PLCSetRegister(PLC_REG_PRESSURE, pressure_value)
		    PLCSetRegister(PLC_REG_RELAY, 1)
                continue
            draw_lines(screen, bottle)

        draw_base(screen, base)
        draw_screen(screen, s)
        draw_ball(screen, limit_switch, THECOLORS['green'])
        draw_ball(screen, level_sensor, THECOLORS['red'])
        #draw_ball(screen, bottle_in, THECOLORS['orange'])


        # screen
        if num_bottles <= 999999: 
            tmp_x, tmp_y = factory_position(550 - (15 * int(len(str(num_bottles))/2)), 133)
        else:
            tmp_x, tmp_y = factory_position(505, 133)
        num_bottles_txt_position_x, num_bottles_txt_position_y = pygame_factory_position(tmp_x, tmp_y)
        count_bottles = fontBig.render(str(num_bottles), 1, THECOLORS['black'])
        screen.blit(count_bottles, (num_bottles_txt_position_x, num_bottles_txt_position_y))

        screen.blit(instructions, (SCREEN_WIDTH-115, 10))
        screen.blit(ip_addr, (SCREEN_WIDTH-100, 20))

	pressure_value = PLCGetRegister(0xb)

        if  pressure_value > 800:
	    pprint.pprint("ROSSO " + str(pressure_value))
            pressure_label = fontBig.render("PRESSURE: " + str(pressure_value), 1, THECOLORS['red'])
        elif pressure_value >= 350 and pressure_value < 800:
     	    pprint.pprint("ARANCIO " + str(pressure_value))
	    pressure_label = fontBig.render("PRESSURE: " + str(pressure_value), 1, THECOLORS['orange'])
        else:
     	    pprint.pprint("VERDE " + str(pressure_value))
	    pressure_label = fontBig.render("PRESSURE: " + str(pressure_value), 1, THECOLORS['green'])
        
        screen.blit(pressure_label, (750, 280))


        draw_beacon(screen, beacon, beacon_color)

        space.step(1/FPS)
        pygame.display.flip()

    # Stop reactor if running
    if reactor.running:
        reactor.callFromThread(reactor.stop)


#########################################
# Modbus Server Code
#########################################

store = ModbusSlaveContext(
    di = ModbusSequentialDataBlock(0, [0]*100),
    co = ModbusSequentialDataBlock(0, [0]*100),
    hr = ModbusSequentialDataBlock(0, [0]*100),
    ir = ModbusSequentialDataBlock(0, [0]*100))

context = ModbusServerContext(slaves=store, single=True)

identity = ModbusDeviceIdentification()
identity.VendorName  = 'MockPLCs'
identity.ProductCode = 'MP'
identity.VendorUrl   = 'http://github.com/bashwork/pymodbus/'
identity.ProductName = 'MockPLC 3000'
identity.ModelName   = 'MockPLC Ultimate'
identity.MajorMinorRevision = '1.0'

def startModbusServer():
    StartTcpServer(context, identity=identity, address=("0.0.0.0", MODBUS_SERVER_PORT))

def main():
    reactor.callInThread(runWorld)
    PLCSetTag(PLC_TAG_RUN, 1)
    PLCSetTag(PLC_TAG_MOTOR, 1)
    startModbusServer()

if __name__ == '__main__':
    sys.exit(main())
