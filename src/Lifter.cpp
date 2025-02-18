#include <Lifter.h>

Lifter::Lifter(std::string& objfile_path)
{
    // check path
    assert(std::filesystem::exists(objfile_path));

    // get the object code
    this->object_file = objfile_path;
}

void Lifter::generateIR(std::string& out_dir)
{
    // check if dir exist, if not create one
    if(std::filesystem::exists(out_dir)) {
        std::filesystem::create_directory(out_dir);
    }

    // Instance of Decompiler
    out_dir += "/lift.ll";
    Decompiler decom(out_dir);

    // load elf
    if(!elf.load(this->object_file))
    {
        std::cerr << "Unable to load the object file" << std::endl;
        exit(1);
    }

    // preprocess elf
    if(!decom.process_elf(elf, this->object_file))
    {
        std::cerr << "Error in preprocessing the elf" << std::endl;
        exit(1);
    }

}

Lifter::~Lifter()
{
}
