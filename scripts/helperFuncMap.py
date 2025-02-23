import os

with open('/usr/include/bpf/bpf_helper_defs.h') as f:
    with open("bpf_function_data.csv", 'w+') as w:
        lines = f.readlines()

        for line in lines:
            if line.startswith('static'):
                line = line.strip(';\n')
                func_ptr_val = line.split('=')[-1].split(' ')[-1].strip()
                return_type = line.split('=')[0].split('(')[0].strip()
                func_name = line.split('=')[0].split('(')[1].strip('*)( ').strip()
                num_par = len(line.split('=')[0].split('(')[2].split(','))                    
                w.write(f"{func_ptr_val},{return_type},{func_name},{num_par}\n")

# import re
# from dataclasses import dataclass
# from typing import List, Optional

# @dataclass
# class Parameter:
#     type: str
#     name: str
    
# @dataclass
# class BPFFunction:
#     name: str
#     return_type: str
#     parameters: List[Parameter]
#     function_id: int

# def parse_bpf_declaration(declaration: str) -> BPFFunction:
#     """
#     Parse a BPF function declaration and return structured information.
    
#     Example input:
#     static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
#     """
#     # Extract function name
#     name_pattern = r'\(\*(\w+)\)'
#     name_match = re.search(name_pattern, declaration)
#     if not name_match:
#         raise ValueError("Could not find function name")
#     func_name = name_match.group(1)
    
#     # Extract return type
#     return_type_pattern = r'^static\s+(\w+)\s+\(\*'
#     return_type_match = re.search(return_type_pattern, declaration)
#     if not return_type_match:
#         raise ValueError("Could not find return type")
#     return_type = return_type_match.group(1)
    
#     # Extract parameters
#     params_pattern = r'\((.*?)\)\s*='
#     params_match = re.search(params_pattern, declaration)
#     if not params_match:
#         raise ValueError("Could not find parameters")
        
#     params_str = params_match.group(1)
#     params = []
    
#     if params_str.strip():
#         # Split parameters and parse each one
#         param_list = [p.strip() for p in params_str.split(',')]
#         for param in param_list:
#             # Handle pointers and const
#             parts = param.split()
#             param_name = parts[-1].replace('*', '').strip()
#             param_type = ' '.join(parts[:-1])
#             params.append(Parameter(type=param_type, name=param_name))
    
#     # Extract function ID
#     id_pattern = r'\(void \*\)\s*(\d+)'
#     id_match = re.search(id_pattern, declaration)
#     if not id_match:
#         raise ValueError("Could not find function ID")
#     func_id = int(id_match.group(1))
    
#     return BPFFunction(
#         name=func_name,
#         return_type=return_type,
#         parameters=params,
#         function_id=func_id
#     )

# def format_function_info(func: BPFFunction) -> str:
#     """Format the parsed function information in a readable way."""
#     params_str = ', '.join(f"{p.type} {p.name}" for p in func.parameters)
#     return f"""Function Information:
#   Name: {func.name}
#   Return Type: {func.return_type}
#   Function ID: {func.function_id}
#   Parameters:
#     {chr(10)+'    '.join(f'- {p.type} {p.name}' for p in func.parameters)}"""

# with open('/usr/include/bpf/bpf_helper_defs.h') as f:
#     with open("bpf_function_data.csv", 'w+') as w:
#         lines = f.readlines()

#         for line in lines:
#             if line.startswith('static'):
#                 print(line)
#                 try:
#                     func = parse_bpf_declaration(line)
#                     print("\nParsing:", line)
#                     print(format_function_info(func))
#                 except ValueError as e:
#                     print(f"Error parsing declaration: {e}")
                
#                 break
