#include <Lifter.h>

Lifter::Lifter(std::string& objfile_path)
{
    // check path
    assert(std::filesystem::exists(objfile_path));

    // get the object code
    this->objcode = bpf_object__open(objfile_path.c_str());

    assert(this->objcode != nullptr);
}

void Lifter::generateIR(std::string& out_dir)
{
    // the object code could have multiple different function
    // need to lift all the functions individually

    // check if dir exist, if not create one
    if(std::filesystem::exists(out_dir)) {
        std::filesystem::create_directory(out_dir);
    } 

    // iterate over each bpf program
    bpf_program* prog;
    bpf_object__for_each_program(prog,this->objcode)
    {
        // as of keep IR for each program different
        std::string prog_name(bpf_program__name(prog));
        std::cout << prog_name << std::endl;
        std::string output_file = out_dir + "/" + prog_name + "_IR.ll";
        ProgLifter prog_lifter(output_file);
    }
}

Lifter::~Lifter()
{
    if(this->objcode != nullptr)
        delete this->objcode;
}
