/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=4 sts=4 sw=4 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 Howard Chu                                                    │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/

#ifndef SYM_H
#define SYM_H

#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>

#define KSYM_PATH "/proc/kallsyms"

#ifndef ARRAY_LEN
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct ksym {
	unsigned long long addr;
	char name[128];
}; 

struct ksyms {
	struct ksym* sym;
	int length;
};

/* Unbelievably similar to ksym */
struct dso_sym {
	unsigned long long addr;
	char name[128];
}; 

struct dso {
	unsigned long long start_addr;
	unsigned long long end_addr;
	unsigned long offset;
	char path[1024];
	struct dso_sym *sym;
	/* dso_sym's length */
	int length;
};

struct usyms {
	struct dso *dsos;
	int length;
};

static int dso_compar(const void *a, const void *b);
static int ksym_compar(const void *a, const void *b);
void remove_space(char* s, int len);
int lines_of_file(FILE* fp);

struct ksyms* ksym_load();
int ksym_init(struct ksyms* ksym_tb, const int length);
int ksym_free(struct ksyms* ksym_tb);
int ksym_addr_to_sym(const struct ksyms *ksym_tb, const unsigned long long addr, char *str);

struct usyms* usym_load(const int *pids, int length);
int usym_init(struct usyms* usym_tb);
int usym_add(struct usyms *usym_tb, const char *path, 
             const unsigned long long start_addr, const unsigned long long end_addr,
			 const unsigned long offset);
int usym_free(struct usyms *usym_tb);
int usym_addr_to_sym(const struct usyms *usym_tb, const unsigned long long addr, char *str);

int dso_load(struct dso *dso_p);
int dso_free(struct dso *dso_p);
int dso_find(const struct usyms* usym_tb, unsigned long long start_addr);
int elf_parse(FILE *fp, struct dso *dso_p);

/* Definition */

#ifdef SYM_H_NO_DEF
#else

// TODO is it good to cast long long to int?
static int dso_compar(const void *a, const void *b)
{
	struct dso_sym *ap, *bp;
	ap = (struct dso_sym*)a;
	bp = (struct dso_sym*)b;

	long long res = (long long)ap->addr - (long long)bp->addr;
	if (res < 0)
		return -1;
	else if (res > 0) 
		return 1;
	else
		return 0;
}

static int ksym_compar(const void *a, const void *b)
{
	unsigned long long a_addr, b_addr;
	a_addr = ((struct ksym*)a)->addr;
	b_addr = ((struct ksym*)b)->addr;

	// just incase
	if (a_addr >= 0xf000000000000000 && b_addr >= 0xf000000000000000) {
		a_addr -= 0xf000000000000000;
		b_addr -= 0xf000000000000000;
	} else if (a_addr >= 0xf000000000000000) {
		return 1;
	} else if (b_addr >= 0xf000000000000000) {
		return -1;
	}

	if (((long long)a_addr - (long long)b_addr) < 0)
		return -1;
	else if (((long long)a_addr - (long long)b_addr) > 0)
		return 1;
	else
		return 0;
}

void remove_space(char* s, int len)
{
	int i = 0, j = 0;
	do {
		while (j < len && s[j] == ' ')
			++j;
		s[i++] = s[j++];
	} while (i < len && j < len);
}

int lines_of_file(FILE* fp)
{
	int cnt = 0;
	char c;
	while (1) {
		int ret = fscanf(fp, "%*llx %c %*s%*[^\n]\n", &c);
		if (ret == EOF)
			break;
		if (ret != 1) {
			printf("Failed to find lines of file\n");
			return -1;
		}
		if (c != 'T' && c != 't')
			continue;
		++cnt;
	}
	rewind(fp);
	return cnt;
}

int ksym_init(struct ksyms *ksym_tb, const int length)
{
	if (ksym_tb == NULL)
		goto sym_init_cleanup;

	ksym_tb->length = length;
	ksym_tb->sym = malloc(sizeof(struct ksym) * length);
	if (ksym_tb->sym != NULL)
		return 0;

sym_init_cleanup:
	free(ksym_tb);
	return -1;
}

struct ksyms* ksym_load()
{
	FILE *fp = fopen(KSYM_PATH, "r");
	int size = lines_of_file(fp);

	struct ksyms* ksym_tb = malloc(sizeof(struct ksyms));
	
	int err = ksym_init(ksym_tb, size);
	if (err) {
		printf("Failed to allocate kernel symbol table of lines: %d\n", size);
		goto ksym_load_cleanup;
	}

	int index = 0;
	unsigned long long addr;
	char c;
	char name[256];

	while (1) {
		int ret = fscanf(fp, "%llx %c %s%*[^\n]\n", &addr, &c, name);
		if (c == 'T' || c == 't') {
			ksym_tb->sym[index].addr = addr;
			strcpy(ksym_tb->sym[index].name, name);
			++index;
		}
		if (ret == EOF)
			break;
		if (ret != 3) {
			printf("Failed to read kernel symbol table\n");
			goto ksym_load_cleanup;
		}
	}

	// sort kernel symbols
	qsort(ksym_tb->sym, ksym_tb->length, sizeof(struct ksym), ksym_compar);

	fclose(fp);
	return ksym_tb;

ksym_load_cleanup:
	fclose(fp);
	ksym_free(ksym_tb);
	ksym_tb = NULL;
	return NULL;
}

int ksym_free(struct ksyms* ksym_tb)
{
	free(ksym_tb->sym);
	ksym_tb->sym = NULL;
	return 0;
}

int ksym_addr_to_sym(const struct ksyms *ksym_tb, unsigned long long addr, char *str)
{
	int low = 0;
	int high = ksym_tb->length - 1;
	int middle;
	int max_high = high;
	unsigned long long middle_addr;
	unsigned long long res_offset = 0;
	int flag = 0;

	if (ksym_tb->length >= 1 && addr > ksym_tb->sym[ksym_tb->length - 1].addr)
		goto ksym_unknown;

	if (ksym_tb->length >= 1 && addr < ksym_tb->sym[0].addr)
		goto ksym_unknown;

	while (low < high) {
		middle = (low + high) / 2;
		middle_addr = ksym_tb->sym[middle].addr;
		if (middle + 1 < ksym_tb->length && middle_addr <= addr && addr < ksym_tb->sym[middle + 1].addr ) {
			res_offset = addr - middle_addr;
			low = middle;
			break;
		} else if (middle == ksym_tb->length - 1 && middle_addr <= addr) {
			res_offset = addr - middle_addr;
			low = middle;
			break;
		} else if (middle_addr > addr) {
			high = middle - 1;
		} else if (middle_addr < addr) {
			low = middle + 1;
		} else if (middle_addr == addr) { // same as user symbol's duplication, just in case.
			res_offset = addr - middle_addr;
			low = middle;
			break;
		}

		if (low > max_high || high < 0) {
			goto ksym_unknown;
		}
	}

	char res[128];

	// TODO: could be used in certain circumstances
	/* with offset */
	// res_offset == 0 ? sprintf(res, "%s",ksym_tb->sym[low].name) : sprintf(res, "%s+0x%llx", ksym_tb->sym[low].name, res_offset);

	sprintf(res, "%s",ksym_tb->sym[low].name);

	strcpy(str, res);
	return 0;

ksym_unknown:
	strcpy(str, "[unknown]");
	return 0;
}

int usym_init(struct usyms *usym_tb) 
{
	usym_tb->dsos = NULL;
	usym_tb->length = 0;
	if (usym_tb == NULL)
		return -1;
	return 0;
}

int usym_add(struct usyms *usym_tb, const char *path, 
             const unsigned long long start_addr, const unsigned long long end_addr,
			 const unsigned long offset)
{
	void *p = realloc(usym_tb->dsos, sizeof(struct dso) * (usym_tb->length + 1));
	if (p == NULL) {
		printf("Failed to reallocate userspace symbol table\n");
		return -1;
	}
	usym_tb->dsos = p;

	struct dso dso_ = {
		.start_addr = start_addr,
		.end_addr = end_addr,
		.sym = NULL,
		.length = 0,
	};
	usym_tb->dsos[usym_tb->length] = dso_;
	struct dso *dso_p = &usym_tb->dsos[usym_tb->length];
	++usym_tb->length;
	/* copy the path after assignment */
	strcpy(dso_p->path, path);

	if (dso_load(dso_p)) {
		printf("Failed to load dso %s\n", dso_p->path);
		return -1;
	}

	// sort dso
	qsort(dso_p->sym, dso_p->length, sizeof(struct dso_sym), dso_compar);

	return 0;
}

struct usyms* usym_load(const int *pids, int length)
{
	struct usyms *usym_tb = malloc(sizeof(struct usyms));
	usym_init(usym_tb);
	FILE* fp;
	char maps_path[256];
	int index, err;
	unsigned long long start_addr, end_addr;
	unsigned int offset;
	char path[1024];
	char last_path[1024];
	char type[5];
	unsigned int inode;

	for (int i = 0;i < length;i++) {
		/* read maps of process to get all dso */
		sprintf(maps_path, "/proc/%d/maps", pids[i]);
		fp = fopen(maps_path, "r");

		index = 0;
		while (1) {
			int ret = fscanf(fp, "%llx-%llx %s %x %*x:%*x %u%[^\n]\n", &start_addr, &end_addr, type, &offset, &inode, path);
			remove_space(path, ARRAY_LEN(path));
			if (ret == EOF)
				break;
			if (inode == 0 || type[3] == 's')
				continue;
			if (ret != 6) {
				printf("Failed to read user maps\n");
				goto usym_load_cleanup;
			}
			/* discard duplicated path */
			if (strcmp(last_path, path) == 0) {
				/* for duplicated path, update the largest address number */
				struct dso *last_dso = &usym_tb->dsos[usym_tb->length - 1];
				last_dso->end_addr = end_addr;
				continue;
			}
			/* duplicated dsos from different pids */
			if (dso_find(usym_tb, start_addr) != -1)
				continue;
			strcpy(last_path, path);
			err = usym_add(usym_tb, path, start_addr, end_addr, offset);
			if (err) {
				printf("Failed to read dso %s\n", path);
				goto usym_load_cleanup;
			}
		}
	}

	fclose(fp);
	return usym_tb;

usym_load_cleanup:
	fclose(fp);
	usym_free(usym_tb);
	free(usym_tb);
	usym_tb = NULL;
	return NULL;
}

int usym_free(struct usyms *usym_tb)
{
	for (int i = 0;i < usym_tb->length; i++) {
		if (dso_free(&usym_tb->dsos[i])) {
			printf("Failed to free userspace symbol table's dso\n");
			exit(-1);
		}
	}
	free(usym_tb->dsos);
	usym_tb->dsos = NULL;
	return 0;
}

// TODO: possible seg fault?
int usym_addr_to_sym(const struct usyms *usym_tb, const unsigned long long addr, char *str)
{
	int low = 0;
	int high = usym_tb->length - 1;
	int middle;
	int max_high = high;
	unsigned long long middle_addr, res_offset = 0;

	/* low is the index of the dso we want */
	low = dso_find(usym_tb, addr);

	if (low == -1)
		goto usym_unknown;

	/* low is the dso index we dive into */
	unsigned long long dso_offset = usym_tb->dsos[low].start_addr;
	struct dso dso_ = usym_tb->dsos[low];

	if (dso_.length <= 0)
		goto usym_unknown;

	low = 0;
	high = dso_.length - 1;
	max_high = high;

	while (low <= high) {

		middle = (low + high) / 2;
		middle_addr = dso_.sym[middle].addr + dso_offset;

		/* corner case: duplicated symbols(middle & middle + 1) */
		if (middle + 1 < dso_.length && middle_addr <= addr && addr < dso_.sym[middle + 1].addr + dso_offset) {
			low = middle;
			res_offset = addr - middle_addr;
			break;
		} else if (middle == dso_.length - 1 && middle_addr <= addr) {
			low = middle;
			res_offset = addr - middle_addr;
			break;
		} else if (middle_addr > addr) {
			high = middle - 1;
		} else if (middle_addr < addr) {
			low = middle + 1;
		} else if (middle_addr == addr) { // this is actually for duplicated symbols
			low = middle;
			res_offset = addr - middle_addr;
			break;
		}

		if (low > max_high || high < 0) {
			goto usym_unknown;
		}
	}

	char res[128];
	// res_offset == 0 ? sprintf(res, "%s",dso_.sym[low].name) : sprintf(res, "%s+0x%llx", dso_.sym[low].name, res_offset);
	sprintf(res, "%s", dso_.sym[low].name);

	strcpy(str, res);
	return 0;

usym_unknown:
	strcpy(str, "[unknown]");
	return 0;
}

int dso_load(struct dso *dso_p)
{
	FILE* fp = fopen(dso_p->path, "rb");
	if (fp == NULL) {
		printf("Failed to open file %s\n", dso_p->path);
		return -1;
	}
	char ident[EI_NIDENT];
	int rc = fread(ident, sizeof(ident), 1, fp);
	int err = 0;
	if (rc != 1) {
		printf("Failed to read ident\n");
		err = -1;
		goto dso_load_cleanup;
	}
	if (ident[0] != 0x7f) {
		printf("%s is not an ELF file\n", dso_p->path);
		err = -1;
		goto dso_load_cleanup;
	}
	/* rewind fp */
	rc = fseek(fp, 0, SEEK_SET);
	if (rc < 0) {
		printf("Failed to rewind\n");
		goto dso_load_cleanup;
	}
	if (ident[4] == ELFCLASS64) {
		err = elf_parse(fp, dso_p);
		if (err != 0) {
			printf("Failed to parse elf file\n");
		}
	} else {
		printf("32-bit ELF not supported\n");
		err = -1;
	}

dso_load_cleanup:
	fclose(fp);
	return err;
}

/*
 * Only need to free dso's sym
 */
int dso_free(struct dso *dso_p)
{
	free(dso_p->sym);
	dso_p->sym = NULL;
	return 0;
}

int dso_find(const struct usyms* usym_tb, unsigned long long addr) {
	if (usym_tb->length == 0)
		return -1;
	for (int i = 0;i < usym_tb->length; i++) {
		if (usym_tb->dsos[i].start_addr <= addr && addr <= usym_tb->dsos[i].end_addr)
			return i;
	}
	return -1;
}

int elf_parse(FILE *fp, struct dso *dso_p)
{
	Elf64_Ehdr ehdr;
	int rc = fread(&ehdr, sizeof(ehdr), 1, fp);
	int err = 0;
	if (rc != 1) {
		printf("Failed to read elf header\n");
		err = -1;
		goto elf_parse_err;
	}

	int num = ehdr.e_phnum;
	int sz = ehdr.e_phentsize;
	unsigned long long offset = ehdr.e_phoff, p_vaddr, p_size;
	Elf64_Phdr phdr;
	int i;
	for (i = 0;i < num; i++) {
		if (fseek(fp, offset, SEEK_SET)) {
			printf("Failed to seek\n");
			err = -1;
			goto elf_parse_err;
		}
		if (fread(&phdr, sizeof(phdr), 1, fp) != 1) {
			printf("Failed to read program header\n");
			err = -1;
			goto elf_parse_err;
		}
		if (phdr.p_flags & PF_X) {
			if (phdr.p_offset == dso_p->offset) {
                p_vaddr = phdr.p_vaddr;
                p_size = phdr.p_memsz; 
				if (p_size == 0) 
					p_size = 0xffffffff;
                break;
            }
		}
		offset += sz;
	}

	if (i >= num) {
		printf("No program headers\n");
		err = -1;
		goto elf_parse_err;
	}

	num = ehdr.e_shnum;
	sz = ehdr.e_shentsize;
	offset = ehdr.e_shoff;
	Elf64_Shdr shdr;
	Elf64_Shdr* headers = malloc(num * sizeof(Elf64_Shdr));

	for (int i = 0;i < num;i++) {
		if (fseek(fp, offset, SEEK_SET) < 0) {
			printf("Failed to seek\n");
			err = -1;
			goto elf_parse_cleanup;
		}
		if (fread(&shdr, sizeof(shdr), 1, fp) != 1) {
			printf("Failed to read section header\n");
			err = -1;
			goto elf_parse_cleanup;
		}
		headers[i] = shdr;
		offset += sz;
	}

	Elf64_Sym symb;
	unsigned long long faddr, fsize;
	unsigned long long size, item_size;

	int link, flink, ix;

	char fname[128];
	for (int i = 0;i < num;i++) {
		switch(headers[i].sh_type) {
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			offset = headers[i].sh_offset;
			size = headers[i].sh_size;
			item_size = headers[i].sh_entsize;
			link = headers[i].sh_link;
			if (link <= 0)
				break;
			for (int j = 0;j + item_size <= size;j += item_size) {
				if (fseek(fp, offset + j, SEEK_SET) < 0)
					continue;
				if (fread(&symb, sizeof(symb), 1, fp) != 1)
					continue;
				if (ELF64_ST_TYPE(symb.st_info) != STT_FUNC )
					continue;
				flink = symb.st_shndx;
				if (flink == 0)
					continue;
				fsize = symb.st_size;
				faddr = symb.st_value;
				if (faddr > p_vaddr + p_size)
					continue;
				ix = symb.st_name;
				if (ix == 0)
					continue;
				if (fseek(fp, headers[link].sh_offset + ix, SEEK_SET) < 0)
					continue;
				if (fgets(fname, sizeof(fname), fp) == NULL)
					continue;
				faddr = faddr - p_vaddr + dso_p->offset;
				dso_p->sym = realloc(dso_p->sym, sizeof(struct dso_sym) * (dso_p->length + 1));
				if (dso_p->sym == NULL)  {
					printf("Failed to add symbol to dso %s\n", dso_p->path);
					err = -1;
					goto elf_parse_cleanup;
				}
				struct dso_sym dso_sym_tmp = {
					.addr = faddr
				};
				dso_p->sym[dso_p->length] = dso_sym_tmp;
				/* copy the name after assignment */
				strcpy(dso_p->sym[dso_p->length].name, fname);
				++dso_p->length;
			}
			break;
		default:
			break;
		}
	}

elf_parse_cleanup:
	free(headers);
	return err;

elf_parse_err:
	return err;
}
#endif // SYM_H_NO_DEF
#endif // SYM_H
