import os


def carve_files(input_file, output_directory):
    # Read the input file as binary
    with open(input_file, 'rb') as f:
        data = f.read()

    # Define file signatures and their corresponding file extensions
    file_signatures = {
        b'\xFF\xD8\xFF\xE0\x00\x10JFIF': ".jpg",
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ".png",
        b'\x50\x4B\x03\x04\x14\x00\x06\x00': ".docx",
        b'\x25\x50\x44\x46\x2D\x31\x2E': ".pdf",
        b'\x00\x00\x00\x20\x66\x74\x79\x70': ".mp4",
        b'\x52\x49\x46\x46\x3C\x00\x00\x00': ".wav",
        b'\x50\x4B\x03\x04\x14\x00\x06\x00': ".xlsx",
        b'\x50\x4B\x03\x04\x14\x00\x08\x00': ".zip",
    }

    # Iterate through the data and search for file signatures
    for signature, extension in file_signatures.items():
        start = 0
        while True:
            # Find the start index of the signature in the data
            start = data.find(signature, start)
            if start == -1:
                break

            # Find the end index of the signature in the data
            end = data.find(b'\xFF\xD9', start)
            if end == -1:
                break

            # Extract the file data
            file_data = data[start:end + 2]
            file_name = f"recovered_{start}{extension}"
            output_path = os.path.join(output_directory, file_name)

            # Write the recovered file to the output directory
            with open(output_path, 'wb') as outfile:
                outfile.write(file_data)

            start = end + 2  # Move to the next potential signature


# Usage example
input_file = "disk_image.bin"
output_directory = "recovered_files"
carve_files(input_file, output_directory)
