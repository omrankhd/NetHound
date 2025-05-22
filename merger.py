import xml.etree.ElementTree as ET
import sys

def merge_nmap_xml(files, output_file):
    first = True
    for file in files:
        tree = ET.parse(file)
        root = tree.getroot()

        if first:
            combined_root = root
            first = False
        else:
            for host in root.findall('host'):
                combined_root.append(host)

    # Write the final merged XML
    tree = ET.ElementTree(combined_root)
    tree.write(output_file)

if __name__ == "__main__":
    import glob
    input_files = glob.glob("*.xml")  # You can customize this
    merge_nmap_xml(input_files, "merged_nmap.xml")
    print(f"Merged {len(input_files)} files into 'merged_nmap.xml'")

