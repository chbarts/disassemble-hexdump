#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>

#include <dis-asm.h>

typedef struct {
    char *insn_buffer;
    bool reenter;
} stream_state;

static int getnext(FILE *in)
{
    int c, i;
    again:
    c = fgetc(in);
    if (EOF == c)
        return -1;
    if (!isalnum(c))
        goto again;
    if (islower(c))
        c &= ~(0x20);
    if ((c < '0') || (c > 'F') || ((c > '9') && (c < 'A')))
        return -2;
    if ((c >= '0') && (c <= '9'))
        i = c - '0';
    else
        i = (c - 'A') + 10;
    return i;
}

static int dis_fprintf(void *stream, const char *fmt, ...)
{
    stream_state *ss = (stream_state *) stream;
    va_list arg;
    va_start(arg, fmt);
    if (!ss->reenter) {
        vasprintf(&ss->insn_buffer, fmt, arg);
        ss->reenter = true;
    } else {
        char *tmp, *tmp2;
        vasprintf(&tmp, fmt, arg);
        asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
        free(ss->insn_buffer);
        free(tmp);
        ss->insn_buffer = tmp2;
    }

    va_end(arg);
    return 0;
}

static char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size, int mach)
{
    size_t pc = 0;
    disassembler_ftype disasm;
    char *disassembled = NULL;
    stream_state ss = {};
    disassemble_info disasm_info = {};
    init_disassemble_info(&disasm_info, &ss, dis_fprintf);
    disasm_info.arch = bfd_arch_i386;
    disasm_info.mach = mach;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = input_buffer;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = input_buffer_size;
    disasm_info.disassembler_options = "intel-mnemonic";
    disassemble_init_for_target(&disasm_info);

    disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
    while (pc < input_buffer_size) {
        size_t insn_size = disasm(pc, &disasm_info);
        pc += insn_size;
        if (disassembled == NULL) {
            asprintf(&disassembled, "%s", ss.insn_buffer);
        } else {
            char *tmp;
            asprintf(&tmp, "%s\n%s", disassembled, ss.insn_buffer);
            free(disassembled);
            disassembled = tmp;
        }

        free(ss.insn_buffer);
        ss.reenter = false;
    }

    return disassembled;    
}

static int disasm(FILE *in, FILE *out, int m)
{
    int res = 0, i, r;
    char *dis;
    uint8_t *buf;
    size_t len = 1024, pc = 0, n = 0;

    if ((buf = malloc(1024)) == NULL) {
        return -4;
    }

    while (1) {
        i = getnext(in);
        if (-1 == i)
            break;
        if (i < 0)
            return i;
        r = i << 4;
        i = getnext(in);
        if (i < 0)
            return i;
        r |= i;
        if ((n + 1) == len) {
            if ((buf = realloc(buf, len * 2)) == NULL) {
                return -4;
             }

             len *= 2;
        }

        buf[n++] = r;
    }

    dis = disassemble_raw(buf, n, m);
    if (fputs(dis, out) == EOF) {
        res = -3;
    } else {
        fputs("\n", out);
    }

    free(dis);
    free(buf);
    return res;
}

static struct option long_options[] = {
    {"input", required_argument, 0, 'i'},
    {"output", required_argument, 0, 'o'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"64-bit", no_argument, 0, '6'},
    {"32-bit", no_argument, 0, '3'},
    {0, 0, 0, 0}
};

static void help(void)
{
    puts("disassemble-hexdump [-3|--32-bit] [-6|--64-bit] [-i|--input INPUT_FILE] [-o|--output OUTPUT_FILE]");
    puts("");
    puts("Turns a hex dump into x86 assembly language.");
    puts("Defaults to x86-64. Use -3 or --32-bit to see i386.");
    puts("Intel syntax.");
    puts("Defaults to stdin and stdout.");
}

static void version(void)
{
    puts("disassemble-hexdump 0.01 by Chris Barts <chbarts@gmail.com> 2022");
}

int main(int argc, char *argv[])
{
    int option_index = 0, exitv, c, m = bfd_mach_x86_64_intel_syntax;
    FILE *in = stdin, *out = stdout;
    char *inf = "stdin", *outf = "stdout";

    while ((c = getopt_long(argc, argv, "i:o:36hv", long_options, &option_index)) != -1) {
        switch (c) {
            case 0:
                switch (option_index) {
                    case 0:
                         inf = optarg;
                         break;
                    case 1:
                         outf = optarg;
                         break;
                    case 2:
                         help();
                         return 0;
                    case 3:
                         version();
                         return 0;
                    case 4:
                        m = bfd_mach_x86_64_intel_syntax;
                        break;
                    case 5:
                        m = bfd_mach_i386_intel_syntax;
                        break;
                }

                break;
            case 'i':
                inf = optarg;
                break;
            case 'o':
                outf = optarg;
                break;
            case '3':
                m = bfd_mach_i386_intel_syntax;
                break;
            case '6':
                m = bfd_mach_x86_64_intel_syntax;
                break;
            case 'h':
                help();
                return 0;
            case 'v':
                version();
                return 0;
            case '?':
                help();
                exit(EXIT_FAILURE);
            default:
                help();
                exit(EXIT_FAILURE);
        }
    }

    if ((strcmp("stdin", inf) != 0) && (in = fopen(inf, "rb")) == NULL) {
        perror("unhexdump couldn't open input");
        exit(EXIT_FAILURE);
    }

    if ((strcmp("stdout", outf) != 0) && (out = fopen(outf, "wb")) == NULL) {
        perror("unhexdump couldn't open output");
        if (stdin != in)
            fclose(in);
        exit(EXIT_FAILURE);
    }

    switch (disasm(in, out, m)) {
    case 0:
        exitv = EXIT_SUCCESS;
        break;
    case -1:
        exitv = EXIT_FAILURE;
        fprintf(stderr, "Unexpected EOF on %s\n", inf);
        break;
    case -2:
        exitv = EXIT_FAILURE;
        fprintf(stderr, "Invalid character on %s\n", inf);
        break;
    case -3:
        exitv = EXIT_FAILURE;
        fprintf(stderr, "Error on output file %s: %s\n", outf, strerror(errno));
        break;
    case -4:
        exitv = EXIT_FAILURE;
        fprintf(stderr, "Memory error\n");
        break;
    default:
        exitv = EXIT_FAILURE;
        fprintf(stderr, "Unknown error\n");
        break;
    }

    if (stdin != in)
        fclose(in);

    if (stdout != out)
        fclose(out);

    exit(exitv);
}
