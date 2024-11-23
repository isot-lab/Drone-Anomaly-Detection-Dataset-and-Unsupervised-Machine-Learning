from djitellopy import Tello
import cv2
import time

def initialize_drone():
    # connect to the Tello drone
    tello = Tello()
    tello.connect()
    
    battery_level = tello.get_battery()
    print(f"Battery level: {battery_level}%")
    return tello

def takeoff(tello):
    tello.takeoff()

def land(tello):
    tello.land()

def move(tello, direction, distance):
    if direction == "up":
        tello.move_up(distance)
    elif direction == "down":
        tello.move_down(distance)
    elif direction == "left":
        tello.move_left(distance)
    elif direction == "right":
        tello.move_right(distance)
    elif direction == "forward":
        tello.move_forward(distance)
    elif direction == "back":
        tello.move_back(distance)

def rotate(tello, degrees):
    if degrees > 0:
        tello.rotate_clockwise(degrees)
    else:
        tello.rotate_counter_clockwise(-degrees)

def main():
    tello = initialize_drone()
    
    takeoff(tello)
    time.sleep(1)
    while True:
        move(tello, "forward", 20)
        time.sleep(1)
        move(tello, "back", 20)
        time.sleep(1)
    
        rotate(tello, 10)
        time.sleep(1)
        rotate(tello, -10)
        time.sleep(1)
        battery_level = tello.get_battery()
        print(f"Battery level: {battery_level}%")

if __name__ == "__main__":
    main()
