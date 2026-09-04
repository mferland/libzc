
/* disable unused functions */
%option noyywrap nounput noinput
%option header-file="mask_scanner.h"

%{
#include "mask_parser.h"
#include <string.h>

void yyerror(const char *format, ...);
int handle_static(const char *yytext, YYSTYPE *yylval);
int handle_placeholder(const char *yytext, YYSTYPE *yylval);
%}

%x rexp

ESCAPED_OR_HEX	\\(.|x[[:xdigit:]]{2})
ALPHANUM	[A-Za-z0-9]
PUNCT		[[:punct:]]
STATIC		{ESCAPED_OR_HEX}|{ALPHANUM}|{PUNCT}

%%

"[" {
    BEGIN(rexp);
    return START_RANGE;
 }

<rexp>"]" {
    BEGIN(INITIAL);
    return END_RANGE;
 }

{STATIC} {
    if (handle_static(yytext, &yylval) == 0)
	return STATIC_CHAR;
    return ERROR;
}

"\?". {
    if (handle_placeholder(yytext, &yylval) == 0)
	return PLACE_HOLDER;
    return ERROR;
}

<rexp>[A-Za-z0-9]-[A-Za-z0-9] {
    yylval.range[0] = yytext[0];
    yylval.range[1] = yytext[2];
    yylval.range[2] = '\0';
    return RANGE;
}

<rexp>{STATIC} {
    if (handle_static(yytext, &yylval) == 0)
	return STATIC_CHAR;
    return ERROR;
}

<rexp>"\?". {
    if (handle_placeholder(yytext, &yylval) == 0)
	return PLACE_HOLDER;
    return ERROR;
}

[ \t\n\r]+   ;

<*>. {
    yyerror("invalid character %c in tokenizer", yytext[0]);
    return ERROR;
}

%%

int handle_static(const char *yytext, YYSTYPE *yylval)
{
    if (yytext[0] == '\\') {
	/*
	 * escaped static characters:
	 * - \a   --> The character 'a'
	 * - \x34 --> The character '4' (0x34 ASCII)
	 * - \?   --> The character '?'
	 * - \\   --> The character '\'
	 */
	if (yytext[1] == 'x' && yytext[2] != '\0') {
	    char *endptr;
	    long decimal = strtol(&yytext[2], &endptr, 16);
	    yylval->sval = decimal;
	} else
	    yylval->sval = yytext[1];
    } else
	yylval->sval = yytext[0];
    return 0;
}

int handle_placeholder(const char *yytext, YYSTYPE *yylval)
{
    switch (yytext[1]) {
    case 'l':
    case 'u':
    case 'd':
    case 's':
    case 'a':
    case 'B':
    case 'b':
    case 'h':
    case 'H':
	yylval->ival = yytext[1];
	return 0;
    default:
	yyerror("unknown place holder value: %c", yytext[1]);
	return -1;
    }
}

void mask_scanner_reset(void)
{
    BEGIN(INITIAL);
}
