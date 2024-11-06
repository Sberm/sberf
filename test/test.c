/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#include "sym.h"
#include "util.h"

void test_ksym()
{
	struct ksyms *ksym_tb = ksym_load();
	if (ksym_tb == NULL)
		DS("Failed to load kernel symbols from test")

	printf("length is %d\n", ksym_tb->length);
	for (size_t i = 0;i < ksym_tb->length; i++) {
		if (ksym_tb->length - i < 10)
			printf("%llx %s\n", ksym_tb->sym[i].addr, ksym_tb->sym[i].name);
	}
}

/* test user symbol loading */
void test_usym() 
{
	int pids[] = {1001};
	struct usyms *usym_tb = usym_load(pids, 1);
	if (usym_tb == NULL)
		DS("Failed to load userspace symbols from test")

	printf("usym_tb size: %d\n", usym_tb->length);

	/* only test first dso */
	const struct dso dso_p = usym_tb->dsos[0];
	printf("usym_tb first dso number of symbols: %d\n", dso_p.length);
	for (size_t i = 0;i < dso_p.length;i++) {
		printf("%llx %s\n", dso_p.sym[i].addr, dso_p.sym[i].name);
	}

	printf("sa %llx ea %llx\n", dso_p.start_addr, dso_p.end_addr);
}

void test_addr_to_name()
{
	struct ksyms* ksym_tb = ksym_load();
	int pids[] = {1001};
	struct usyms *usym_tb = usym_load(pids, 1);

	if (ksym_tb != NULL && usym_tb != NULL)
		printf("Successfully loaded\n");

	char name[256];
	unsigned long long addr;

	addr = 0xffffffffc0340220;
	ksym_addr_to_sym(ksym_tb, addr, name);
	printf("kernel symbol: %s\n" ,name);

	char temp[256];

	addr = 0x26c40;
	addr += usym_tb->dsos[0].start_addr;
	printf("%llx\n",addr);

	usym_addr_to_sym(usym_tb, addr, name);
	printf("got user symbol: [%s]\n" ,name);
}

void test_random() {
	/* 8 8 */
	int len = 20;
	char *p = malloc(len);
	strcpy(p + 10, "fuck");
	for (int i = 0;i < len; i++) {
		if (p[i] == 0)
			printf("%d", i);
		else
			printf("%c", p[i]);
	} printf("\n");

	free(p);
}

int main() 
{
	test_ksym();

	test_usym();

	test_addr_to_name();

	test_random();
	return 0;
}
