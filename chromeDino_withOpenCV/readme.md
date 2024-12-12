# Chrome Dino with Open CV

## Description
Simple bot that can automatically play the Chrome Dinosaur Game using OpenCV for Computer Vision. The bot will identify obstacles and control the game dynamically by simulating key presses.

## Installation
You need..
- Python 3.x 
- OpenCV (for image processing) (opencv-python==4.5.5.64)
- Numpy (for some operations) (numpy==1.22.4)
- PyAutoGui (GUI interactions, keyboard input) (pyautogui==0.9.53)
- Pillow (dependency of PyAutoGUI) (pillow==9.1.0)
  
```bash
pip install opencv-python numpy pyautogui pillow
```
use this command to install

## Run
1. Open chrome://dino/ in your browser and run main.py.
2. Define the obstacle detection area (ROI) by dragging on the screen, then press Space or Enter to proceed. (chromeDino_withOpenCV/setROI.png?raw=true)
3. Start the game and enjoy! (chromeDino_withOpenCV/play_demo.gif?raw=true)

## License 
This project is licensed under the MIT License.
Feel free to modify!

## Acknowledgements
Check this link for OpenCV tutorials
https://docs.opencv.org/4.x/d6/d00/tutorial_py_root.html

This project is inspired by Code Bullet
https://www.youtube.com/@CodeBullet/videos