import os
import re
import logging

logger = logging.getLogger(__name__)

def pyFiles():
    
    python_files = []
    files = os.listdir()
    while files:
        file = files.pop(0)
        if file.endswith(".py"):
            python_files.append(file)

        elif os.path.isdir(file) and not file.endswith("tests"):
            files.extend([os.path.join(file, f) for f in os.listdir(file)])

    python_files.remove(os.path.relpath(__file__))
    return python_files
def get_relative_import_path(file_path):
    depth = file_path.count(os.sep)
    return 'from ' + ('.' * depth) + 'debug import config'
    
def helper(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    initfile = False
    classname = ""
    if os.path.split(file_path)[-1]=="__init__.py":
        classname = os.path.basename(os.path.dirname(file_path))
        initfile = True
    
    message = f"Initializing {classname} " if initfile else "Running - "
    has_imports = 0
    has_logging = False
    new_lines = []
    import_logging = f"{get_relative_import_path(file_path)}\nimport logging\nlogger = logging.getLogger(__name__)\n"
    ignoreidx = 0

    for i in range(len(lines)):
        if lines[i].startswith('def') or (has_imports > 0 and lines[i]=="\n") or has_logging: 
            for j in range(i, len(lines)):
                new_lines.append(lines[j])
            break

        if has_imports==0 and (lines[i].startswith('"') or lines[i].startswith("'") or lines[i].startswith('#') or lines[i]=="\n"):
            ignoreidx +=1

        else:
            sline = lines[i].strip()
            if sline.startswith('import ') or sline.startswith('from '):
                if "from debug" in sline:
                    has_logging = True
                has_imports += 1
            else:
                ignoreidx += 1

        new_lines.append(lines[i])
  
    if not has_logging:

        logger.debug("Importing logger")
        new_lines.insert(ignoreidx + has_imports, import_logging)
        i = 0
        in_function = False
        while True:

            if i == len(new_lines):
                break
            line = new_lines[i]
            if re.match(r'^\s*def\s+\w+\s*\(', line):
                in_function = True

            if in_function:
                if re.match(r'.*\)\s*:\s*$', line):
                    indentation = re.match(r'^\s*', line).group()
                    new_lines.insert(i + 1, f'{indentation}    logger.debug("{message}")\n')
                    in_function = False
            i += 1

    with open(file_path, 'w') as file:
        file.writelines(new_lines)

def logFile(files): 

    no_of_files = len(files)
    if no_of_files == 0:
        raise ValueError("No Python files found.")
    
    logger.debug(f"Python files found: {no_of_files}")
    for filepath in files:
        helper(filepath)


if __name__ == "__main__":

    python_files = pyFiles()
    print(f"A Total of {len(python_files)} Python files were found (excluding `tests` directory).")
    logFile(python_files)
