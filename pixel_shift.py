import numpy as np

def reverse_shift_pixels(image):
    pixel_data = np.array(image)
    height, width, channels = pixel_data.shape
    shifted = np.zeros_like(pixel_data)
    for i in range(height):
        for j in range(width):
            shift_val = (height * width - (i * width + j)) % 256
            shifted[i, j] = (pixel_data[i, j] + shift_val) % 256
    return shifted

def reverse_unshift_pixels(image):
    pixel_data = np.array(image)
    height, width, channels = pixel_data.shape
    unshifted = np.zeros_like(pixel_data)
    for i in range(height):
        for j in range(width):
            shift_val = (height * width - (i * width + j)) % 256
            unshifted[i, j] = (pixel_data[i, j] - shift_val) % 256
    return unshifted