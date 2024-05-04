/*-*- coding:utf-8                                                          -*-│
│vi: set ft=c ts=8 sts=8 sw=8 fenc=utf-8                                    :vi│
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

#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include "stack.h"
#include "plot.h"
#include "util.h"
#define SYM_H_NO_DEF // don't include definition of sym.h, because it is included in record.c
#include "sym.h"

static int blue[] = {
	0x42E5CA,
	0x5395E5,
	0x69E5AA,
	0x67BAE6,
	0x2DC5E5,
};

static int pink[] = {
	0xFEE3EC,
	0xF9C5D5,
	0xF999B7,
	0xF2789F,
};

static int flame[] = {
	0xFFF78A,
	0xFFE382,
	0xFFC47E,
	0xFFAD84,
};

static const char css[] = "<style type=\"text/css\">\n"
			  "text { font-size:12px; fill:rgb(0,0,0); }\n"
			  "</style>\n";

static const char js[] = "<script><![CDATA[\n"
" function main(evt) {\n"
"     let g = document.querySelectorAll('g');\n"
"     g.forEach((gi) => {\n"
"         let rect = gi.querySelector('rect');\n"
"         let title = gi.querySelector('title');\n"
"         let content = title.textContent;\n"
"         let text = gi.querySelector('text');\n"
"         text.textContent = content;\n"
"         let width = rect.width.baseVal.value;\n"
"         console.log(text.getSubStringLength(0, content.length), width);\n"
"         if (text.getSubStringLength(0, content.length) <= width) {\n"
"             return;\n"
"         }\n"
"         for (let i = content.length - 1; i >= 0; --i) {\n"
"             if (text.getSubStringLength(0, i + 1) <= width) {\n"
"                 text.textContent = content.substring(0, i) + '..';\n"
"                 return;\n"
"             }\n"
"         }\n"
"         text.innerHTML = \"\";\n"
"     });\n"
" }\n"
"]]></script>\n";

int color_index = 0;
int *color_palette;
int color_palette_sz;

char* svg_str;
int svg_sz = 65536;
int svg_index = 0;

#define MAX_WIDTH 1200.0
double max_height = 0;

// x start
#define X_ST 10.0

enum PLOT_MODE {
	PLOT_CYCLE,
	PLOT_OFF_CPU,
} plot_mode;

void __plot(struct stack_ag* p, unsigned long long p_cnt, double x, double len, int depth, struct ksyms* ksym_tb, struct usyms* usym_tb)
{
	if (p == NULL)
		return;

	double y = depth * FRAME_HEIGHT;
	double width = ((double)p->cnt / (double)p_cnt) * len;
	double height = FRAME_HEIGHT;
	int c = color_palette[color_index];
	char frame_title[128];
	char g_str[1024];

	color_index = color_index + 1 > color_palette_sz - 1 ? 0 : color_index + 1;

	if (p->addr == 0 && !p->is_comm) {
		strcpy(frame_title, "all");
	} else if (p->is_comm) {
		strcpy(frame_title, p->comm);
	} else {
		addr_to_sym(ksym_tb, usym_tb, p->addr, frame_title);
	}

	switch (plot_mode) {
	case PLOT_CYCLE:
		snprintf(g_str, sizeof(g_str), " <g>\n"
					       " <title>%s (%%%.2f)</title><rect x=\"%.2f\" y=\"%.2f\""
					       " width=\"%.2f\" height=\"%.2f\" fill=\"#%06x\""
					       " rx=\"2\" ry=\"2\" />\n"
					       " <text  x=\"%.2f\" y=\"%.2f\" ></text>\n"
					       " </g>\n",
					       frame_title, width / MAX_WIDTH * 100, x, y, width, height,
					       c, x + 0.2, y + FRAME_HEIGHT - 4);
		break;
	case PLOT_OFF_CPU:
		snprintf(g_str, sizeof(g_str), " <g>\n"
					       " <title>%s (%.3fs)</title><rect x=\"%.2f\" y=\"%.2f\""
					       " width=\"%.2f\" height=\"%.2f\" fill=\"#%06x\""
					       " rx=\"2\" ry=\"2\" />\n"
					       " <text  x=\"%.2f\" y=\"%.2f\" ></text>\n"
					       " </g>\n",
					       frame_title, ((double)p->cnt / 1000000000ULL), x, y, width, height,
					       c, x + 0.2, y + FRAME_HEIGHT - 4);
		break;
	default:
		break;
	}
	

	/* realloc just like a stl vector */
	if (svg_index + strlen(g_str) >= svg_sz) {
		svg_sz *= 2;
		svg_str = realloc(svg_str, sizeof(char) * svg_sz);
	}

	strcpy(svg_str + svg_index , g_str);
	svg_index += strlen(g_str);

	__plot(p->next, p_cnt, x + width, len, depth, ksym_tb, usym_tb);

	__plot(p->child, p->cnt, x, width, depth + 1, ksym_tb, usym_tb);
}

int plot_off_cpu(struct stack_ag *p, char* file_name, pid_t* pids, int num_of_pids)
{
	struct ksyms* ksym_tb;
	struct usyms* usym_tb;

	if (p == NULL)
		return -1;

	max_height = stack_get_depth(p) * FRAME_HEIGHT;

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

	color_palette = pink;
	color_palette_sz = ARRAY_LEN(pink);
	
	plot_mode = PLOT_OFF_CPU;
	
	/* write svg to svg_str */
	__plot(p, p->cnt, X_ST, MAX_WIDTH, 0, ksym_tb, usym_tb);

	fprintf(fp, "<svg version=\"1.1\" width=\"%.0f\" height=\"%.0f\" onload=\"main(evt)\" viewBox=\"0 0 %.0f %.0f\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n", MAX_WIDTH + 5, max_height + 5, MAX_WIDTH + 5, max_height + 5);

	fputs(css, fp);
	fputs(js, fp);
	fputs(svg_str, fp); // use fprintf here will cause seg fault

	fprintf(fp, "</svg>\n");

cleanup:
	free(svg_str);
	fclose(fp);
	ksym_free(ksym_tb);
	usym_free(usym_tb);

	return 0;
}

int plot(struct stack_ag *p, char* file_name, pid_t* pids, int num_of_pids)
{
	struct ksyms* ksym_tb;
	struct usyms* usym_tb;

	if (p == NULL)
		return -1;

	max_height = stack_get_depth(p) * FRAME_HEIGHT;

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

	color_palette = flame;
	color_palette_sz = ARRAY_LEN(flame);

	plot_mode = PLOT_CYCLE;
	
	__plot(p, p->cnt, X_ST, MAX_WIDTH, 0, ksym_tb, usym_tb);

	fprintf(fp, "<svg version=\"1.1\" width=\"%.0f\" height=\"%.0f\" onload=\"main(evt)\" viewBox=\"0 0 %.0f %.0f\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n", MAX_WIDTH + 18, max_height + 18, MAX_WIDTH + 18, max_height + 18);

	fputs(css, fp);
	fputs(js, fp);
	fputs(svg_str, fp); // use fprintf here will cause SEGV

	fprintf(fp, "</svg>\n");

cleanup:
	free(svg_str);
	fclose(fp);
	ksym_free(ksym_tb);
	usym_free(usym_tb);

	return 0;
}
