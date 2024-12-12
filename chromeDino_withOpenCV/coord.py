import pyautogui
import time

def track_mouse():
    """Function to track mouse position and return the selected position."""
    print("Press Ctrl+C to stop tracking the mouse position.")
    try:
        while True:
            x, y = pyautogui.position()  # Get the current mouse position.
            print(f"Mouse position: ({x}, {y})", end="\r")  # Print on the same line continuously.
            time.sleep(0.1)  # Pause briefly to reduce CPU load.
    except KeyboardInterrupt:
        print(f"\nSelected position: ({x}, {y})")
        return x, y

print("Select the top-left and bottom-right coordinates of the rectangular area.")

# Track the top-left corner coordinates
print("\nSelect the top-left corner coordinates.")
top_left = track_mouse()

# Track the bottom-right corner coordinates
print("\nSelect the bottom-right corner coordinates.")
bottom_right = track_mouse()

# Print the results
print("\nCoordinates of the rectangular area:")
print(f"Top-left: {top_left}")
print(f"Bottom-right: {bottom_right}")
