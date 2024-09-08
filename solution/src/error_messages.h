

#ifndef OWL_ELF_LOADER_ERROR_MESSAGES
#define OWL_ELF_LOADER_ERROR_MESSAGES

#include <errno.h>
#define PRINT_ERROR_AND_EXIT(message) { write(STDERR_FILENO, (message), sizeof((message))); _exit(errno); }

#define OPEN_FAILED "Could not open a file!"
#define ARGUMENT_WRONG_COUNT "Incorrect amount of arguments. Expected: 2"
#define LSEEK_FAILED "This is bug! Contact the developer with this info: LSEEK"
#define READ_FAILED "This is likely a bug! Contact the developer with this info: LSEEK"
#define MPROTECT_FAILED "This is bug! Contact the developer with this info: MPROTECT"
#define MMAP_FAILED "This is bug! Contact the developer with this info: MMAP"
#define UNEXPECTED_EOF "Unexpected end of file!"
#define NO_STRING_TABLE "Provided ELF file does not have string table.\n Therefore could not find section by its name!"
#define INVALID_ELF "Provided file is not a valid ELF!"
#define SECTION_NAME_COMPARISON_FAILED "Section name comparison failed"

#endif

