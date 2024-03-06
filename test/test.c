#include "sym.h"
#include "util.h"

/* test user symbol loading */
void test_usym() 
{
	int pid = 1001;
	struct usyms *usym_tb = usym_load(pid);
	if (usym_tb == NULL) {
		DS("Failed to load userspace symbols from test")
	}
	printf("usym_tb size: %d\n", usym_tb->length);
	/* only test first dso */
	struct dso dso_p = usym_tb->dsos[0];
	printf("usym_tb first dso number of symbols: %d\n", dso_p.length);
	for (size_t i = 0;i < dso_p.length;i++) {
		printf("%llx %s\n", dso_p.sym[i].addr, dso_p.sym[i].name);
	}
}

int main() 
{
	test_usym();
	return 0;
}
