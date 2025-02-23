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
