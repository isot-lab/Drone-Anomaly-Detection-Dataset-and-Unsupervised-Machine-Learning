from djitellopy import Tello
import time

def initialize_drone():
    tello = Tello()
    tello.connect()
    
    battery_level = tello.get_battery()
    print(f"Battery level: {battery_level}%")
    tello.streamon()
    return tello

def main():
    tello = initialize_drone()
    while True:
       time.sleep(1)

if __name__ == "__main__":
    main()
