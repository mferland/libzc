%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <errno.h>
#include <stdarg.h>
#include "mask_scanner.h"
#include "list.h"

int yylex(void);

void yyerror(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "mask parse error: ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
}

struct mask_item {
	char *set;
	struct list_head list;
};

static struct mask_item *current_range = NULL;
static struct list_head item_head;

static void *xcalloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (!p)
		yyerror("calloc() failed");
	return p;
}

static void dealloc_item(struct mask_item *e)
{
	free(e->set);
	free(e);
}

static void dealloc_item_list(struct list_head *head)
{
	struct mask_item *e, *tmp;
	list_for_each_entry_safe(e, tmp, head, list) {
		list_del(&e->list);
		dealloc_item(e);
	}
}

static int alloc_mask_item(struct mask_item **e, size_t nmemb, size_t size)
{
	struct mask_item *tmp;

	tmp = xcalloc(1, sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	tmp->set = xcalloc(nmemb, size);
	if (!tmp->set) {
		free(tmp);
		return -ENOMEM;
	}

	*e = tmp;

	return 0;
}

static struct mask_item * make_range_core(int first, int second)
{
	struct mask_item *e;
	int ret, i, j;

	if (first > second) {
		yyerror("invalid range %c-%c", first, second);
		return NULL;
	}

	ret = alloc_mask_item(&e, second - first + 2, sizeof(unsigned char));
	if (ret)
		return NULL;

	for (i = first, j = 0; i <= second; ++i, ++j)
		e->set[j] = i;

	return e;
}

static struct mask_item * make_range_alphanum(int first, int second)
{
	if ((islower(first) && islower(second)) ||
	    (isupper(first) && isupper(second)) ||
	    (isdigit(first) && isdigit(second)))
		return make_range_core(first, second);

	yyerror("invalid range %c-%c", first, second);
	return NULL;
}

static struct mask_item * make_char(int c)
{
	struct mask_item *e;
	int ret;

	/* if (isalpha(c) || isdigit(c) || c == '-' || c == '\\') { */
		ret = alloc_mask_item(&e, 2, sizeof(unsigned char));
		if (ret)
			return NULL;
		e->set[0] = c;
		return e;
	/* } */

	yyerror("invalid character %c", c);
	return NULL;
}

static struct mask_item * make_place_holder(int place_holder)
{
	struct mask_item *e = NULL;

	switch (place_holder) {
	case 'l':
		/* lower case */
		e = make_range_alphanum('a', 'z');
		break;
	case 'u':
		/* upper case */
		e = make_range_alphanum('A', 'Z');
		break;
	case 'd':
		/* numbers */
		e = make_range_alphanum('0', '9');
		break;
	case 's':
		/* special characters */
		e = calloc(1, sizeof(*e));
		e->set = strdup(" !\"#$%&'()*+,-./:;<=>?`[~]^_{|}@\\");
		break;
	case 'a':
		/* full printable ASCII */
		e = make_range_core(32, 126);
		break;
	case 'B':
		/* all 8-bit */
		e = make_range_core(0x80, 0xff);
		break;
	case 'b':
		/* all (except NULL character) */
		e = make_range_core(0x01, 0xff);
		break;
	case 'h':
		/* lowercase HEX digits */
		e = calloc(1, sizeof(*e));
		e->set = strdup("abcdef0123456789");
		break;
	case 'H':
		/* uppercase HEX digits */
		e = calloc(1, sizeof(*e));
		e->set = strdup("ABCDEF0123456789");
		break;
	}

	return e;
}

void print_item(const struct mask_item *e)
{
	printf("%s\n", e->set);
}

static struct mask_item * range_merge(struct mask_item *e)
{
	char *tmp;
	size_t len;

	if (!current_range)
		return current_range = e;

	len = strlen(current_range->set) + strlen(e->set) + 1;
	tmp = realloc(current_range->set, len);
	if (!tmp) {
		yyerror("realloc() failed");
		dealloc_item(current_range);
		dealloc_item(e);
		current_range = NULL;
		return NULL;
	}
	current_range->set = tmp;
	strcat(current_range->set, e->set);
	dealloc_item(e);

	return current_range;
}

static void item_add_tail(struct mask_item *e)
{
	list_add_tail(&e->list, &item_head);
}

%}

%code provides {
int parse_mask(const char *input, char ***output);
}

%code {
int parse_mask(const char *input, char ***output)
{
	struct mask_item *item;
	YY_BUFFER_STATE buffer;
	int ret;
	char **tmp;

	INIT_LIST_HEAD(&item_head);

	buffer = yy_scan_string(input);

	ret = yyparse();
	if (ret) {
		ret = -1;
		goto err_del_buffer;
	}

	list_for_each_entry(item, &item_head, list)
		ret++;

	tmp = xcalloc(ret, sizeof(char*));
	if (!tmp) {
		ret = -1;
		goto err_dealloc_items;
	}

	ret = 0;
	list_for_each_entry(item, &item_head, list) {
		tmp[ret++] = strdup(item->set);
	}

	*output = tmp;

err_dealloc_items:
	dealloc_item_list(&item_head);
err_del_buffer:
	yy_delete_buffer(buffer);
	return ret;
}

}

%union {
    int   ival;    /* single char or range endpoint */
    int   sval;
    char  range[3];/* range "a-z" stored as 2 chars + '\0' */
    struct mask_item *item;    /* AST node */
}

/* --- Tokens with typed values --- */
%token <sval> STATIC_CHAR
%token <range> RANGE
%token <ival> PLACE_HOLDER
%token START_RANGE END_RANGE ERROR

/* --- Nonterminals with types --- */
%type <item> expr literal_seq range range_contents range_item place_holder

%%

input
    : expr       { item_add_tail($1); }
    | input expr { item_add_tail($2); }
    ;

expr
    : literal_seq   { $$ = $1; }
    | range         { $$ = $1; }
    | place_holder  { $$ = $1; }
    ;

literal_seq
    : STATIC_CHAR {
	    $$ = make_char($1);
	    if (!$$) YYABORT;
 }
    ;

range
    : START_RANGE range_contents END_RANGE {
	    $$ = $2;
	    current_range = NULL;
 }
    ;

range_contents
    : range_item {
	    $$ = range_merge($1);
	    if (!$$) YYABORT;
 }
    | range_contents range_item {
	    $$ = range_merge($2);
	    if (!$$) YYABORT;
 }
    ;

range_item
    : STATIC_CHAR  {
	    $$ = make_char($1);
	    if (!$$) YYABORT;
 }
    | RANGE {
	    $$ = make_range_alphanum($1[0], $1[1]);
	    if (!$$) YYABORT;
 }
    | PLACE_HOLDER {
	    $$ = make_place_holder($1);
	    if (!$$) YYABORT;
 }
    ;

place_holder
    : PLACE_HOLDER {
	    $$ = make_place_holder($1);
	    if (!$$) YYABORT;
 }
    ;

%%
