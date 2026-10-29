// Check schema JSON with the same Schema::parseJSON as ebpf-compile.
// Output one <file>\tok or <file>\terror\t<message> per file. Exit 1 for
// invalid schemas, 2 for unreadable files. See docs/schema_format.md.
#include "bpf-mlir/Target/EBPF/Schema.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static cl::list<std::string> files(cl::Positional, cl::desc("<schema.json>..."), cl::OneOrMore);

int main(int argc, char **argv) {
  cl::ParseCommandLineOptions(argc, argv, "bpf-mlir schema JSON validation (docs/schema_format.md)\n");
  int rc = 0;
  for (const std::string &f : files) {
    auto buf = MemoryBuffer::getFile(f);
    if (!buf) {
      errs() << "ebpf-schema-check: cannot read " << f << ": " << buf.getError().message() << "\n";
      return 2;
    }
    auto s = ebpf::Schema::parseJSON((*buf)->getBuffer());
    if (!s) {
      std::string msg = toString(s.takeError());
      for (char &c : msg)
        if (c == '\n' || c == '\t')
          c = ' ';
      outs() << f << "\terror\t" << msg << "\n";
      rc = 1;
      continue;
    }
    outs() << f << "\tok\n";
  }
  return rc;
}
