#include <iostream>
#include <Lifter.h>

int main(int argc, char** argv)
{
    if(argc < 2) {
        std::cerr << "Format: " << argv[0] << " bytecode_filepath output_dir" << std::endl;
        return 1;
    }

    std::string inpath(argv[1]);
    std::string outpath(argv[2]);
    Lifter t(inpath);
    t.generateIR(outpath);
    return 0;
}