#### Command

Run the script with: `python3 main.py ./images/ ./detected_circles/ 2.5`

* Arguments
    * `./images/` → Input directory containing images
    * `./detected_circles/` → Output directory for cropped results
    * `2.5` → Crop scale

---

#### Setup

* Install dependencies (Ubuntu)

    ```bash
    sudo apt update
    sudo apt install python3-pip python3-dev libgl1
    ```

* Create and activate virtual environment

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

* Install Python dependencies

    ```bash
    pip install opencv-python numpy
    ```

---

#### Build (CMake)

```bash
cmake -S . -B build
```