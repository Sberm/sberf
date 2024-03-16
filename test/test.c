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
	/* sa 55e8c50bf000 ea 55e8c50dc000 */
	/* 55e8c50e1da0 55e8c51939f0*/
	printf("sa %llx ea %llx\n", dso_p.start_addr, dso_p.end_addr);
}

void test_addr_to_name()
{
	struct ksyms* ksym_tb = ksym_load();
	int pids[] = {1001};
	struct usyms *usym_tb = usym_load(pids, 1);

	if (ksym_tb != NULL && usym_tb != NULL) {
		printf("Successfully loaded\n");
	}

	char name[256];
	unsigned long long addr;

	addr = 0xffffffffc0340220;
	ksym_addr_to_sym(ksym_tb, addr, name);
	printf("kernel symbol: %s\n" ,name);

	/*const struct dso dso_p = usym_tb->dsos[0];*/
	/*printf("dso_p's info: s_a %llx e_a %llx\n", dso_p.start_addr, dso_p.end_addr);*/

	/* supposed to be 55e8c4de0ef7 ngx_hash_init+0x2b7, but got ngx_write_channel */
	/*addr = 0x55e8c4de0ef7;*/

	char temp[256];

	// addr = usym_tb->dsos[0].sym[17].addr;
	// addr += usym_tb->dsos[0].start_addr;
	// strcpy(temp, usym_tb->dsos[0].sym[17].name);
	// printf("searching [%s]\n", temp);
	// 0x55E8C4DE0C40
	
	addr = 0x26c40;
	addr += usym_tb->dsos[0].start_addr;
	printf("%llx\n",addr);

	usym_addr_to_sym(usym_tb, addr, name);
	printf("got user symbol: [%s]\n" ,name);
}

void test_random() {
	/* 8 8 */
	// printf("%d %d\n", sizeof(unsigned long), sizeof(unsigned long long));
	int len = 20;
	char *p = malloc(len);
	strcpy(p + 10, "fuck");
	for (int i = 0;i < len; i++) {
		if (p[i] == 0)
			printf("%d", i);
		else
			printf("%c", p[i]);
	} printf("\n");
}

int main() 
{
	// test_ksym();
 	// test_usym();
	// test_addr_to_name();
	// test_random();
	DS("%d\n", 1);
	
	return 0;
}
