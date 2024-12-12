import cv2
import numpy as np
import pyautogui
import time

# Screen capture function
def capture_screen():
    # Capture the entire screen using pyautogui
    screenshot = pyautogui.screenshot()
    # Convert from RGB to BGR for OpenCV processing
    screenshot = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
    return screenshot
         
# ROI selection function
def select_roi(image):
    # Use OpenCV's selectROI
    print("Set the ROI: Drag and press Enter or Spacebar. Press Esc to cancel.")
    roi = cv2.selectROI("Set ROI", image, showCrosshair=True, fromCenter=False)
    cv2.destroyAllWindows()
    return roi  # (x, y, width, height)

# Obstacle detection function
def detect_obstacle(image, roi):
    x, y, w, h = roi
    roi_image = image[y:y+h, x:x+w]
    # Convert the ROI to grayscale
    gray = cv2.cvtColor(roi_image, cv2.COLOR_BGR2GRAY)
    # Count dark pixels (brightness < 100)
    dark_pixels = np.sum(gray < 100)
    print(f"Number of dark pixels: {dark_pixels}")
    
    # Consider it an obstacle if the number of dark pixels exceeds a threshold
    return dark_pixels > 40 # Threshold for dark pixels

# Jump function
def jump():
    pyautogui.press('space')
    print("Jump!")

# Main execution logic
def main():
    # Screen capture
    screen = capture_screen()
                      
    # ROI selection
    roi = select_roi(screen)

    # Check the ROI
    if roi[2] == 0 or roi[3] == 0:
        print("ROI selection was canceled.")
        return

    print(f"Selected ROI: x={roi[0]}, y={roi[1]}, width={roi[2]}, height={roi[3]}")

    # Game loop
    print("Starting the game loop. Press Ctrl+C to exit.")
    try:
        while True:
            # Screen capture
            screen = capture_screen()

            # Obstacle detection
            if detect_obstacle(screen, roi):
                jump()

            # Set delay    
            time.sleep(0.2)  # Wait for 200ms
    except KeyboardInterrupt:
        print("Exiting the game loop.")

if __name__ == "__main__":
    main()
