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

struct color {
	unsigned char r;
	unsigned char g;
	unsigned char b;
};

static struct color colors[] = {
	{.r = 117, .g = 106, .b = 182},
	{.r = 172, .g = 135, .b = 197},
	{.r = 224, .g = 174, .b = 208},
	{.r = 255, .g = 229, .b = 229},
};

int color_index = 0;

float max_width = 1200;
float max_height = 2500;

const float x_st = 10;
const int depth_st = 0;

void plot_prvt(struct stack_ag* p, int p_cnt, float x, float len, int depth, FILE* fp)
{
	if (p == NULL)
		return;

	float y = depth * FRAME_HEIGHT;
	float width = ((float)p->cnt / (float)p_cnt) * len;
	float height = FRAME_HEIGHT;

	struct color c = colors[color_index];
	color_index = color_index + 1 > ARRAY_LEN(colors) - 1 ? 0 : color_index + 1;

	char frame_title[1024];
	// sprintf(frame_title, "%s", p->name);
	sprintf(frame_title, " ");

	fprintf(fp, "<g>\n"
	            "<title>%s(%%%.2f)</title><rect x=\"%.2f\" y=\"%.2f\" width=\"%.2f\" height=\"%.2f\" fill=\"rgb(%d,%d,%d)\" rx=\"1.5\" ry=\"1.5\" />\n"
	            "<text  x=\"%.2f\" y=\"%.2f\" >%s</text>\n"
	            "</g>\n", frame_title, width/max_width*100, x, y, width, height, c.r, c.g, c.b,
	                      x + 0.2, y + FRAME_HEIGHT - 0.1 , frame_title);

	
	/* brothers */
	plot_prvt(p->next, p_cnt, x + width, len, depth, fp);

	/* children */
	plot_prvt(p->child, p->cnt, x, width, depth + 1, fp);
}

void plot(struct stack_ag *p, char* name_of_plot)
{
	if (p == NULL)
		return;

	char file_name[1024];
	sprintf(file_name, "%s.svg", name_of_plot);

	FILE* fp = fopen(file_name, "w");

	fprintf(fp, "<svg version=\"1.1\" width=\"%.0f\" height=\"%.0f\" onload=\"init(evt)\" viewBox=\"0 0 %.0f %.0f\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n", max_width, max_height, max_width, max_height);

	plot_prvt(p, p->cnt, x_st, max_width, depth_st, fp);

	fprintf(fp, "</svg>\n");

	fclose(fp);
}

