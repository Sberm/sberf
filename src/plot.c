/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Howard Chu                                                    │
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

#include <stdlib.h>
#include "stack.h"
#include "plot.h"
#include "util.h"
#define SYM_H_NO_DEF // don't include definition of sym.h, because it is included in record.c
#include "sym.h"

static int colors[] = {
	0x42E5CA,
	0x5395E5,
	0x69E5AA,
	0x67BAE6,
	0x2DC5E5,
};

static const char css[] = "<style type=\"text/css\">\ntext { font-size:12px; fill:rgb(0,0,0); }\n</style>\n";
static const char javascript[] = "<script><![CDATA[\n"
" function main(evt) {\n"
"     let g = document.querySelectorAll('g');\n"
"     g.forEach((gi) => {\n"
"         let rect = gi.querySelector('rect');\n"
"         let title = gi.querySelector('title');\n"
"         let content = title.textContent;\n"
"         let text = gi.querySelector('text');\n"
"         text.textContent = content;\n"
"         let width = rect.width.baseVal.value;\n"
"         let a = \"\";\n"
"         let i = 0;\n"
"         console.log(text.getSubStringLength(0, content.length), width);\n"
"         if (text.getSubStringLength(0, content.length) <= width) {\n"
"             return;\n"
"         }\n"
"         for (let i = content.length; i >= 0; --i) {\n"
"             if (text.getSubStringLength(0, i) <= width) {\n"
"                 text.textContent = content.substring(0, i);\n"
"                 return;\n"
"             }\n"
"         }\n"
"         text.innerHTML = \"\";\n"
"     });\n"
" }\n"
" ]]></script>\n";

/* kernel symbol table */
struct ksyms* ksym_tb;
/* user symbol table */
struct usyms* usym_tb;

int color_index = 0;

int svg_sz = 65536;
int svg_index = 0;
char* svg_str;

float max_width = 1200;
float max_height = 1700;

const float x_st = 10;
const int depth_st = 0;

void plot_prvt(struct stack_ag* p, int p_cnt, float x, float len, int depth)
{
	if (p == NULL)
		return;

	float y = depth * FRAME_HEIGHT;
	float width = ((float)p->cnt / (float)p_cnt) * len;
	float height = FRAME_HEIGHT;

	int c = colors[color_index];
	color_index = color_index + 1 > ARRAY_LEN(colors) - 1 ? 0 : color_index + 1;

	char frame_title[128];

	/* find symbol of current frame's address */
	if (p->addr == 0) // root
		strcpy(frame_title, "root");
	else
		addr_to_sym(ksym_tb, usym_tb, p->addr, frame_title);

	char g_str[1024];

	sprintf(g_str, "<g>\n"
	               "<title>%s (%%%.2f)</title><rect x=\"%.2f\" y=\"%.2f\" width=\"%.2f\" height=\"%.2f\" fill=\"#%x\" rx=\"2\" ry=\"2\" />\n"
	               "<text  x=\"%.2f\" y=\"%.2f\" ></text>\n"
	               "</g>\n", frame_title, width / max_width*100, x, y, width, height, c,
	                      x + 0.2, y + FRAME_HEIGHT - 4);

	/* realloc just like a stl vector */
	if (svg_index + strlen(g_str) >= svg_sz) {
		svg_sz *= 2;
		svg_str = realloc(svg_str, sizeof(char) * svg_sz);
	}

	strcpy(svg_str + svg_index , g_str);
	svg_index += strlen(g_str);

	/* brothers */
	plot_prvt(p->next, p_cnt, x + width, len, depth);

	/* children */
	plot_prvt(p->child, p->cnt, x, width, depth + 1);
}

int plot(struct stack_ag *p, char* file_name, pid_t* pids, int num_of_pids)
{
	if (p == NULL)
		return -1;

	/* symbol table */
	ksym_tb = ksym_load();
	usym_tb = usym_load(pids, num_of_pids);
	if (ksym_tb == NULL || usym_tb == NULL) {
	    printf("Failed to load symbols when plotting\n");
		return -1;
	}
	
	FILE* fp = fopen(file_name, "w");

	svg_str = malloc(sizeof(char) * svg_sz);
	memset(svg_str, 0, sizeof(char) * svg_sz);

	if (svg_str == NULL) {
		printf("Failed to allocate memory for writing svg\n");
		fclose(fp);
		return -1;
	}
	
	/* write svg to svg_str */
	plot_prvt(p, p->cnt, x_st, max_width, depth_st);

	fprintf(fp, "<svg version=\"1.1\" width=\"%.0f\" height=\"%.0f\" onload=\"main(evt)\" viewBox=\"0 0 %.0f %.0f\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n", max_width + 18, max_height + 18, max_width + 18, max_height + 18);

	fputs(css, fp);
	fputs(javascript, fp);
	fputs(svg_str, fp); // use fprintf here will cause seg fault

	fprintf(fp, "</svg>\n");

cleanup:
	free(svg_str);
	fclose(fp);
	ksym_free(ksym_tb);
	usym_free(usym_tb);

	return 0;
}
