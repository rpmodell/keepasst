/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of the  nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include "kdbx.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <ctype.h>

#include <curses.h>
#include <openssl/crypto.h>

#define PASS_BUF_MAX 512
#define ERR_BUF_MAX 1024

#define CTRL(x) ((x) & 0x1f)
#define SEL_ATTRON(W, C, T) wattron(W, C == T ? COLOR_PAIR(1) : A_REVERSE)
#define SEL_ATTROFF(W, C, T) wattroff(W, C == T ? COLOR_PAIR(1) : A_REVERSE)

enum wintype {
	WGROUPS, WENTRIES, WENTRY
};

struct kpt_ctx {
	char *db_path;
	uint8_t epassword[PASS_BUF_MAX];
	ssize_t epassword_len;
	uint8_t key[32];
	WINDOW *head_win;
	WINDOW *groups_win;
	WINDOW *entries_win;
	WINDOW *entry_win;
	WINDOW *status_win;
	int error;
	char errstr[ERR_BUF_MAX];

	int current;
	int hide_protected;
	int group_sel;
	int entry_sel;
	int value_sel;
};

void die(const char *args, ...)
{
	va_list ap;
	va_start(ap, args);
	endwin();
	vfprintf(stderr, args, ap);
	fputs("\n", stderr);
	va_end(ap);
	exit(-1);
}

static inline void set_current_db_path(struct kpt_ctx *ctx, const char *path)
{
	if (ctx->db_path) {
		free(ctx->db_path);
		ctx->db_path = NULL;
	}

	if (path)
		ctx->db_path = str_clone(path);
}

static int set_password(struct kpt_ctx *ctx, const char *password)
{
	size_t len = strlen(password);
	if (crypto_fill_rand_buf(ctx->key, 16))
		return -1;

	if ((ctx->epassword_len = encrypt_chacha20(ctx->epassword, (uint8_t*) password, len + 1, ctx->key + 16, ctx->key)) < 0)
		return -2;

	return 0;

}

static char *get_password(struct kpt_ctx *ctx)
{
	char *pass = (char*) crypto_secure_malloc(ctx->epassword_len * sizeof(char));
	if (!pass) die("secure allocation failed!");
	memset(pass, 0, ctx->epassword_len);

	if (encrypt_chacha20((uint8_t*) pass, ctx->epassword, ctx->epassword_len, ctx->key + 16, ctx->key) < 0)
		return NULL;


	return pass;

}

static int add_default_entry(KDBXGroup *group, const char *name)
{
	KDBXEntry *entry = entry = kdbx_group_add_entry(group, 0);
	if (!entry)
		return -1;

	kdbx_entry_put_value(entry, "Title", name);
	kdbx_entry_put_value(entry, "UserName", "user0");
	kdbx_entry_put_value(entry, "Password", "password1234");
	kdbx_entry_set_protected(entry, 2, 1);
	kdbx_entry_put_value(entry, "URL", "http://example.com");
	kdbx_entry_put_value(entry, "Notes", "notes");

	return 0;
}

static void set_error(struct kpt_ctx *ctx, const char *args, ...)
{
	va_list ap;
	va_start(ap, args);
	ctx->error = 1;
	vsnprintf(ctx->errstr, sizeof(ctx->errstr), args, ap);

	va_end(ap);
}

WINDOW *new_dialog(int width, int height)
{
	WINDOW *win;
	int startx, starty;

	startx = getmaxx(stdscr) / 2 - width / 2;
	starty = getmaxy(stdscr) / 2 - height / 2;

	win = newwin(height, width, starty, startx);
	keypad(win, 1);
			 
					 
	return win;
}

static WINDOW *new_window(int width, int height, int startx, int starty)
{
	WINDOW *win;
	win = newwin(height, width, starty, startx);		 
	keypad(win, 1);
	return win;
}

static inline void resize_window(WINDOW *win, int width, int height, int startx, int starty)
{
	wresize(win, height, width);
	mvwin(win, starty, startx);
	wrefresh(win);
}

int input_prompt(WINDOW *win, const char *title, const char *prompt, int hidden, char *out, ssize_t outlen)
{
	ssize_t i;
	int start, ch;

	wclear(win);
	box(win, 0, 0);
	mvwprintw(win, 0, 1, "%s", title);

	mvwprintw(win, 2, 2, "%s: ", prompt);
	wrefresh(win);
	
	keypad(win, 1);
	wmove(win, 3, 2);
	for (i = 0; i < outlen;) {
		ch = wgetch(win);
		if (ch == '\n')
			break;

		switch (ch) {
		case KEY_BACKSPACE:
			if ((--i) < 0)
				i = 0;

			out[i] = '\0';
			if (i < 36) {
				mvwaddch(win, 2, 1 + i, ' ');
				wmove(win, 2, 1 + i);
			}
			break;
		default:
			if (i < 36)
				waddch(win, hidden ? '*' : ch);
			out[i++] = ch;
			break;
		}

		wrefresh(win);
	}

	out[i] = '\0';


}

static int head_refresh(struct kpt_ctx *ctx)
{
	int px = getmaxx(ctx->head_win) - (ctx->db_path ? strlen(ctx->db_path) : 4) - 2;
	wclear(ctx->head_win);
	wbkgd(ctx->head_win, COLOR_PAIR(1));
	wprintw(ctx->head_win, "keepasst v0.1", ctx->db_path);
	mvwprintw(ctx->head_win, 0, px, "[%s]", ctx->db_path ? ctx->db_path : "null");
	wrefresh(ctx->head_win);
}



static int groups_refresh(WINDOW *win, int current, int sel, KDBX *db)
{
	size_t i;
	int j, xmax = 0, pad = 0;

	xmax = getmaxx(win);
	werase(win);
	wattron(win, A_BOLD);
	mvwprintw(win, 0, 0, "%s", "Groups");
	wattroff(win, A_BOLD);
	for (i = 0; i < db->groups_count; i++) {
		if (i == sel) 
			SEL_ATTRON(win, current, WGROUPS);

		pad = xmax - strlen(db->groups[i].name);
		mvwprintw(win, i + 1, 0, "%s", db->groups[i].name);
		
		for (j = 0; j < pad; j++)
			waddch(win, ' ');
			
		if (i == sel) 
			SEL_ATTROFF(win, current, WGROUPS);
	}
	wrefresh(win);
}


static inline int groups_loop(struct kpt_ctx *ctx, KDBX *db, int key)
{
	switch (key) {
	case KEY_UP:
		ctx->group_sel = MAX(0, ctx->group_sel - 1);
		ctx->entry_sel = 0;
		break;		
	case KEY_DOWN:
		ctx->group_sel = MIN(db->groups_count - 1, ctx->group_sel + 1);		
		ctx->entry_sel = 0;
		break;
	case 'a':
		kdbx_add_group(db, "Group");
		ctx->group_sel = 0;
		break;
	case 'd':
		if (db->groups_count > 1) {
			kdbx_remove_group(db, ctx->group_sel);
		}
		break;
	}

	return groups_refresh(ctx->groups_win, ctx->current, ctx->group_sel, db);
}

static int entries_refresh(WINDOW *win, KDBXGroup *group, int current, int sel)
{
	size_t i;
	int j, xmax = 0, ymax = 0, pad = 0;
	char *title = NULL;

	xmax = getmaxx(win);
	ymax = getmaxy(win);

	werase(win);
	wvline(win, ACS_VLINE, ymax);

	if (!group)
		return 0;

	wattron(win, A_BOLD);
	mvwprintw(win, 0, 1, "%s", "Entries");
	wattroff(win, A_BOLD);
	for (i = 0; i < group->entries_count; i++) {
		if (i == sel) 
			SEL_ATTRON(win, current, WENTRIES);

		title = kdbx_entry_get_value(&group->entries[i], "Title");
		if (title) {
			pad = xmax - strlen(title) - 1;
			mvwprintw(win, i + 1, 1, "%s", title);
		} else {
			pad = xmax - 5 - 1 - 2;
			mvwprintw(win, i + 1, 1, "Entry%zu", i + 1);
		}
		
		for (j = 0; j < pad; j++)
			waddch(win, ' ');
			
		if (i == sel) 
			SEL_ATTROFF(win, current, WENTRIES);
	}

	wrefresh(win);
}


static inline int process_entries(struct kpt_ctx *ctx, KDBX *db, int key)
{
	KDBXGroup *group = &db->groups[ctx->group_sel];
	switch (key) {
	case KEY_UP:
		ctx->entry_sel = MAX(0, ctx->entry_sel - 1);
		ctx->value_sel = 0;
		break;		
	case KEY_DOWN:
		ctx->entry_sel = MIN(group->entries_count - 1, ctx->entry_sel + 1);		
		ctx->value_sel = 0;
		break;
	case 'a':
		add_default_entry(group, "Entry");
		ctx->entry_sel = 0;
		break;
	case 'd':
		if (group->entries_count > 1) {
			kdbx_group_remove_entry(group, ctx->entry_sel);
		}
		break;
	}

	return entries_refresh(ctx->entries_win, group, ctx->current, ctx->entry_sel);
}

static int entry_refresh(WINDOW *win, KDBXEntry *entry, int current, int hide, int sel)
{
	size_t i;
	int j, vlen = 0, xmax = 0, ymax = 0, pad = 0;
	xmax = getmaxx(win);
	ymax = getmaxy(win);

	werase(win);
	wvline(win, ACS_VLINE, ymax);
	if (sel < 0) {
		return 0;
	}

	wattron(win, A_BOLD);
	mvwprintw(win, 0, 1, "%s", "Key");
	mvwprintw(win, 0, 15, "%s", "Value");
	if (entry->time_info.expiration) {
		char datebuf[128];
		struct tm *tm = localtime(&entry->time_info.expiration);
		strftime(datebuf, sizeof(datebuf), "%Y/%m/%d %H:%M:%S", tm);
		mvwprintw(win, 0, xmax - 29, "[Expires %s]", datebuf);
	}
	wattroff(win, A_BOLD);
	for (i = 0; i < entry->values_count; i++) {
		if (i == sel) 
			SEL_ATTRON(win, current, WENTRY);

		pad = 15 - strlen(entry->values[i].key);
		mvwprintw(win, i + 1, 1, "%s", entry->values[i].key);
		for (j = 0; j < pad; j++)
		 	waddch(win, ' ');
		
		pad = xmax - 15;
		vlen = strlen(entry->values[i].value);
		if (entry->values[i].protect && (hide || i != sel)) {
			wmove(win, i + 1, 15);
			for (j = 0; j < vlen; j++)
		 		waddch(win, '*');		
		} else {
			mvwprintw(win, i + 1, 15, "%s", entry->values[i].value);
		}
		
		pad -= vlen;
		for (j = 0; j < pad; j++)
		 	waddch(win, ' ');

		if (i == sel) 
			SEL_ATTROFF(win, current, WENTRY);
	}

	wrefresh(win);
	return 0;
}

static int entry_value_edit(WINDOW *win, KDBXEntry *entry, int current, int sel)
{
	int i, xmax = 0, start = 0, len = 0, protect = 0;
	xmax = getmaxx(win);
	start = 15;
	protect = entry->values[sel].protect;
	len = strlen(entry->values[sel].value);
	wmove(win, sel + 1, start + len);
	SEL_ATTRON(win, current, WENTRY);

	char out[2048];
	memset(out, 0, sizeof(out));
	int c = 0;
	int outlen = sizeof(out);
	i = len;
	while (i >= 0 && i < outlen) {
		c = wgetch(win);
		if (c == '\n')
			break;

		switch (c) {
			case KEY_BACKSPACE:
			if (i > 0)
				out[i--] = '\0';


			mvwaddch(win, sel + 1, start + i, ' ');
			wmove(win, sel + 1, start + i);
			break;
		default:
			waddch(win, c);

			out[i++] = c;
			break;
		}

		wrefresh(win);
	}

	SEL_ATTROFF(win, current, WENTRY);

	out[i] = '\0';
	kdbx_entry_set_value(entry, sel, out);
	return 0;
}

static inline int process_entry(struct kpt_ctx *ctx, KDBX *db, int key)
{
	KDBXGroup *group = &db->groups[ctx->group_sel];
	KDBXEntry *entry = &group->entries[ctx->entry_sel];
	switch (key) {
	case KEY_UP:
		ctx->value_sel = MAX(0, ctx->value_sel - 1);
		break;		
	case KEY_DOWN:
		ctx->value_sel = MIN(entry->values_count - 1, ctx->value_sel + 1);		
		break;
	case 's':
	case ' ':
		ctx->hide_protected = !ctx->hide_protected;
		break;	
	case 'e':
		entry_value_edit(ctx->entry_win, entry, ctx->current, ctx->value_sel);
		entries_refresh(ctx->entries_win, group, ctx->current, ctx->entry_sel);
		break;
	case 'p':
		kdbx_entry_set_protected(entry, ctx->value_sel, !entry->values[ctx->value_sel].protect);
		break;
	}
	return entry_refresh(ctx->entry_win, entry, ctx->current, ctx->hide_protected, ctx->value_sel);
}

static inline void refresh_ctx(struct kpt_ctx *ctx, KDBX *db)
{
	groups_refresh(ctx->groups_win, ctx->current, ctx->group_sel, db);
	entries_refresh(ctx->entries_win, &db->groups[ctx->group_sel], ctx->current, ctx->entry_sel);
	entry_refresh(ctx->entry_win, &db->groups[ctx->group_sel].entries[ctx->entry_sel], ctx->current, 1, ctx->value_sel);
	head_refresh(ctx);
}


static int write_db(struct kpt_ctx *ctx, KDBX *db)
{
	int ret = -1;
	char *pass = get_password(ctx);
	if (!pass)
		return -1;

	kdbx_generate_salts(db);
	ret = kdbx_write(db, ctx->db_path, pass);
	crypto_secure_free(pass);

	return ret;
}

static int choose_password(struct kpt_ctx *ctx, KDBX *db)
{
	int i, ret;
	char *pwdbuf = crypto_secure_malloc(PASS_BUF_MAX);
	char *pwdbuf2 = crypto_secure_malloc(PASS_BUF_MAX);
	KDBXGroup *root = NULL;
	WINDOW *pass_win = new_dialog(40, 7);
	memset(pwdbuf, 0, sizeof(pwdbuf));
	memset(pwdbuf2, 0, sizeof(pwdbuf));

	for (i = 0; i < 3; i++) {
		if (input_prompt(pass_win, "Choose a password", "Password", 1, pwdbuf, PASS_BUF_MAX)) {
			//ret = -1;
			//break;
		}
		if (input_prompt(pass_win, "Choose a pasword", "Confirm password", 1, pwdbuf2, PASS_BUF_MAX)) {
			//ret = -1;
			//break;
		}

		if ((ret = strcmp(pwdbuf, pwdbuf2)) == 0)
			break;
	}

	if (ret == 0) 
		set_password(ctx, pwdbuf);

	crypto_secure_free(pwdbuf);
	crypto_secure_free(pwdbuf2);
	delwin(pass_win);
	return ret;
}

static int process_cmd(struct kpt_ctx *ctx, KDBX *db)
{

	char cmdbuf[512];
	char *saveptr = NULL;
	char *tok = NULL, *tok1 = NULL;
	ssize_t index;
	int i, ch, ret = 0;
	KDBXGroup *group = NULL;

	wclear(ctx->status_win);
	wbkgd(ctx->status_win, COLOR_PAIR(1));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	waddch(ctx->status_win, '/');
	for (i = 0; i < sizeof(cmdbuf);) {
		ch = wgetch(ctx->status_win);
		if (ch == '\n') {
			break;
		} else if (ch == 27) {
			return 0;
		} else if (ch == KEY_BACKSPACE) {
			if ((--i) < 0)
				i = 0;

			cmdbuf[i] = '\0';
			mvwaddch(ctx->status_win, 0, i + 1, ' ');
			wmove(ctx->status_win, 0, i + 1);
		} else if (isprint(ch)) {
			cmdbuf[i++] = ch;
			waddch(ctx->status_win, ch);
		}
	}

	tok = strtok_r(cmdbuf, " ", &saveptr);
	if (!strcmp(tok, "quit")) {
		// save db etc
		endwin();
		exit(0);
	} else if (!strcmp(tok, "group")) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (!strcmp(tok, "add")) {
			tok = strtok_r(NULL, " ", &saveptr);
			if (!tok) {
				set_error(ctx, "group add command requires name");
				return -1;
			}
			group = kdbx_add_group(db, tok);
			add_default_entry(group, "Default");
			ctx->group_sel = 0;
		} else if (!strcmp(tok, "del")) {
			tok = strtok_r(NULL, " ", &saveptr);
			if (db->groups_count == 1) {
				set_error(ctx, "At least one group should exisis");
				return -1;
			}

			index = tok ? kdbx_find_group(db, tok) : ctx->group_sel;
			switch (index) {
			case -1:
				set_error(ctx, "Group '%s' does not exists", tok);
				return -1;
			case 0:
				set_error(ctx, "Group 'Root' cannot be removed");
				return -1;
			default:
				if (kdbx_remove_group(db, index)) {
					set_error(ctx, "error removing group '%s'", tok);
					return -1;
				}
				break;
			}
			ctx->group_sel = 0;
		} else if (!strcmp(tok, "rename")) {
			tok = strtok_r(NULL, " ", &saveptr);
			tok1 = strtok_r(NULL, " ", &saveptr);
			char *name = NULL;
			if (tok && tok1) {
				index = kdbx_find_group(db, tok);
				name = tok1;
			} else if (tok) {
				index = ctx->group_sel;
				name = tok;
			} else {
				set_error(ctx, "command requires at least an argument", tok);
				return -1;
			}

			switch (index) {
			case -1:
				set_error(ctx, "Group '%s' does not exists", tok);
				return -1;
			case 0:
				set_error(ctx, "Group 'Root' cannot be renamed");
				return -1;
			default:
				if (kdbx_group_set_name(db, index, name)) {
					set_error(ctx, "error rename group '%s'", tok);
					return -1;
				}
				break;
			};
		} else if (!strcmp(tok, "setexpiry")) {
			struct tm tm;
			memset(&tm, 0, sizeof(struct tm));
			tok = strtok_r(NULL, " ", &saveptr);
			tok1 = strtok_r(NULL, " ", &saveptr);
			if (tok && tok1) {
				strptime(tok1, "%Y/%m/%dT%H:%M:%S", &tm);
				index = kdbx_find_group(db, tok);
				if (index < 0) {
					set_error(ctx, "Group '%s' does not exists", tok);
					return -1;
				}
			} else if (tok) {
				strptime(tok, "%Y/%m/%dT%H:%M:%S", &tm);
				index = ctx->group_sel;
			} else {
				return -1;
			}

			db->groups[index].time_info.expiration = mktime(&tm);
		} else if (!strcmp(tok, "unsetexpiry")) {
			tok = strtok_r(NULL, " ", &saveptr);
			if (tok) {
				index = kdbx_find_group(db, tok);
				if (index < 0) {
					set_error(ctx, "Group '%s' does not exists", tok);
					return -1;
				}
			} else {
				index = ctx->group_sel;
			}

			db->groups[index].time_info.expiration = 0;
		} else {
			set_error(ctx, "error unrecognized group command %s", tok);
			return -1;
		}
	} else if (!strcmp(tok, "entry")) {
		tok = strtok_r(NULL, " ", &saveptr);
		group = &db->groups[ctx->group_sel];
		if (!strcmp(tok, "add")) {
			tok = strtok_r(NULL, " ", &saveptr);
			if (!tok)
				return -1;
			
			add_default_entry(group, tok);
			ctx->entry_sel = 0;
		} else if (!strcmp(tok, "del")) {
			if (group->entries_count > 1) {
				kdbx_group_remove_entry(group, ctx->entry_sel);
			} else {
				return -1;
			}
		} else if (!strcmp(tok, "setexpiry")) {
			struct tm tm;
			memset(&tm, 0, sizeof(struct tm));
			tok = strtok_r(NULL, " ", &saveptr);
			if (strptime(tok, "%Y/%m/%dT%H:%M:%S", &tm) == NULL) {
				set_error(ctx, "invalid datetime", tok);
				return -1;
			}
			group->entries[ctx->entry_sel].time_info.expiration = mktime(&tm);
		} else if (!strcmp(tok, "unsetexpiry")) {
			group->entries[ctx->entry_sel].time_info.expiration = 0;
		} else {
			set_error(ctx, "error unrecognized entry command %s", tok);
			return -1;
		}
	} else if (!strcmp(tok, "write")) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (tok) {
			set_current_db_path(ctx, tok);
		} else if (!ctx->db_path) {
			set_error(ctx, "error path is null, plase specify a path");
			return -1;	
		}

		if ((ret = write_db(ctx, db))) {
			set_error(ctx, "error writing db %s", kdbx_strerror(ret)); 
			return -1;
		}
	} else if (!strcmp(tok, "set")) {
		tok = strtok_r(NULL, " ", &saveptr);
		if (!strcmp(tok, "compressed")) {
			tok = strtok_r(NULL, " ", &saveptr);
			if (!tok) {
				set_error(ctx, "set command requires an argument");
				return -1;
			}

			if (!strcmp(tok, "yes")) {
				db->compressed = 1;
			} else if (!strcmp(tok, "no")) {
				db->compressed = 1;
			} else {
				set_error(ctx, "invalid boolean value '%s'", tok);
				return -1;		
			}
		} else if (!strcmp(tok, "kdf")) {
			tok = strtok_r(NULL, " ", &saveptr);
			if (!tok) {
				set_error(ctx, "set command requires an argument");
				return -1;
			}

			if (!strcmp(tok, "argon2d")) {
				kdbx_set_kdf_type(db, KDBX_KDF_ARGON_2D);
			} else if (!strcmp(tok, "argon2id")) {
				kdbx_set_kdf_type(db, KDBX_KDF_ARGON_2ID);
			} else if (!strcmp(tok, "aes")) {
				kdbx_set_kdf_type(db, KDBX_KDF_AES);
			} else {
				set_error(ctx, "unknown kdf type '%s'", tok);
				return -1;		
			}
		} else if (!strcmp(tok, "password")) {
			ret = choose_password(ctx, db);
			refresh();
			if (ret) {
				set_error(ctx, "error setting new password");
				return -1;
			}
		} else {
			set_error(ctx, "error unrecognized set command %s", tok);
			return -1;	
		}
	} else {
		set_error(ctx, "unknown command %s", tok);
		return -1;
	}

	return 0;
}

static int status_refresh(struct kpt_ctx *ctx, KDBX *db)
{
	if (ctx->error) { 
		wclear(ctx->status_win);
		wbkgd(ctx->status_win, COLOR_PAIR(3));
		wprintw(ctx->status_win, "Error: %s [press any key]", ctx->errstr);
		wrefresh(ctx->status_win);
		wgetch(ctx->status_win);
		ctx->error = 0;
	}
	
	wclear(ctx->status_win);
	wbkgd(ctx->status_win, COLOR_PAIR(1));
	wprintw(ctx->status_win, "[q] quit | [w] Write | ");
	switch (ctx->current) {
	case WGROUPS:
		wprintw(ctx->status_win, "[a] Add Group | [d] Delete Group");
		break;
	case WENTRIES:
		wprintw(ctx->status_win, "[a] Add Entry | [d] Delete Entry");
		break;
	case WENTRY:
		wprintw(ctx->status_win, "[e] Edit Value | [p] Toggle hidden");
		if (db->groups[ctx->group_sel].entries[ctx->entry_sel].values[ctx->value_sel].protect) {
			wprintw(ctx->status_win, " | [s] Show Value");
		}
		break;
	}
	wrefresh(ctx->status_win);
	return 0;
}

static void quit(struct kpt_ctx *ctx, KDBX *db)
{
	int ret = 0, ch;
	//FIXME introduce edited concept in ctx;
	wclear(ctx->status_win);
	wbkgd(ctx->status_win, COLOR_PAIR(1));
	wprintw(ctx->status_win, "Do you want to [(q)uit, (w)rite and quit, (c)ancel]? ");
	wrefresh(ctx->status_win);
	switch ((ch = wgetch(ctx->status_win))) {
	case 'w':
		if ((ret = write_db(ctx, db))) {
			set_error(ctx, "fail write db: %s", kdbx_strerror(ret));
			return;
		}
	case 'q':
		endwin();
		exit(0);
		break;
	case 'c':
		return;
	default:
		set_error(ctx, "invalid option '%c'", ch);
		return;
	}
}

static int open_db(struct kpt_ctx *ctx, KDBX *db, const char *dbpath)
{
	int i, ret;
	WINDOW *pass_win = new_dialog(40, 7);
	char *pwdbuf = crypto_secure_malloc(PASS_BUF_MAX);
	memset(pwdbuf, 0, PASS_BUF_MAX);

	for (i = 0; i < 3; i++) {
		if (input_prompt(pass_win, "Unlock DB", "Password", 1, pwdbuf, PASS_BUF_MAX)) {
		}

		if ((ret = kdbx_read(db, dbpath, pwdbuf)) == 0)
			break;	// test1:hi_dude_how_you_doing, test3:mcduckte
	}

	if (ret == 0) {
		set_current_db_path(ctx, dbpath);
		set_password(ctx, pwdbuf);
	}

	crypto_secure_free(pwdbuf);
	delwin(pass_win);
	return ret;
}

static int create_db(struct kpt_ctx *ctx, KDBX *db, const char *dbpath)
{
	int i, ret;
	KDBXGroup *root = NULL;
	if (choose_password(ctx, db))
		return -1;

	set_current_db_path(ctx, dbpath);
	kdbx_init(db);
	root = kdbx_add_group(db, "Root");
	add_default_entry(root, "Default");

	return 0;
}

#if 0
int main(int argc, char **argv)
{

	switch (argc) {
	case 1:
		break;
	case 2:
		KDBX db;
		kdbx_init(&db);
		int ret = kdbx_read(&db, argv[1], "mcducktest");
		fprintf(stderr, "kdf=%d, kdf_salt_len=%zu, parall=%d, memory=%ld, version=0x%x, iters=%ld, inner=%d\n", 
				db.kdf_type, db.kdf_salt_len, db.kdf.kdf_argon2.parallelism, db.kdf.kdf_argon2.memory, db.kdf.kdf_argon2.version, db.kdf.kdf_argon2.iterations
				, db.inner_encr);

		size_t i, j, k;
		for (i = 0; i < db.groups_count; i++) {
			fprintf(stderr, "g[%zu] = %s\n", i, db.groups[i].name);
			for (j = 0; j < db.groups[i].entries_count; j++) {
				fprintf(stderr, "\t-------------\n");
				for (k = 0; k < db.groups[i].entries[j].values_count; k++) {
				
					fprintf(stderr, "\t%s = %s\n", db.groups[i].entries[j].values[k].key, db.groups[i].entries[j].values[k].value);
				}
			}
		}
		
		// db.compressed = 0;
	ret =	kdbx_write(&db, "out.kdbx", "mcducktest");
		fprintf(stderr, "\n REsult %d\n", ret);
		break;
	}
}
#else
int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "-h")) {
		printf("usage: %s [-h] <kdbxfile>\n", argv[0]);
		exit(0);
	}

	KDBX db;
	kdbx_init(&db);

	int xmax, ymax, key, ret = 0;
	char pwdbuf[512];

	initscr();
	cbreak();
	noecho();

	start_color();
	init_pair(1, COLOR_WHITE, COLOR_BLUE);
	init_pair(2, COLOR_BLUE, COLOR_BLACK);
	init_pair(3, COLOR_WHITE, COLOR_RED);

	keypad(stdscr, 1);


	refresh();
	
	struct stat statbuf;
	struct kpt_ctx ctx;
	ctx.db_path = NULL;
	ctx.error = 0;
	memset(ctx.errstr, 0, sizeof(ctx.errstr));

	switch (argc) {
	case 1:
		if (create_db(&ctx, &db, NULL))
			die("error: cannot create db: %s", strerror(errno));
		
		break;
	case 2:
		if (stat(argv[1], &statbuf)) {
			if (errno == ENOENT) {
				if (create_db(&ctx, &db, NULL))
					die("error: cannot create db: %s", strerror(errno));
			} else {
				die("error: cannot open file: %s, ", strerror(errno));
			}
		} else {
			if ((ret = open_db(&ctx, &db, argv[1])))
				die("error: open db failed: %s", kdbx_strerror(ret));
		}
		break;
	default:
		die("too many arguments");
	}


	raw();
	clear();

	refresh();


	xmax = getmaxx(stdscr);
	ymax = getmaxy(stdscr);

	ctx.head_win = new_window(xmax, 1, 0, 0);
	ctx.groups_win = new_window(xmax / 8, ymax - 2, 0, 1);
	ctx.group_sel = 0;
	ctx.entries_win = new_window(xmax / 8, ymax - 2, xmax / 8, 1);
	ctx.entry_sel = 0;
	ctx.entry_win = new_window(xmax - (xmax / 4), ymax - 2, xmax / 4, 1);
	ctx.entry_sel = 0;
	ctx.status_win = new_window(xmax, 1, 0, ymax - 1);
	ctx.current = WGROUPS;
	ctx.hide_protected = 1;
	
	int current = WGROUPS;
	groups_refresh(ctx.groups_win, WGROUPS, 0, &db);
	process_entries(&ctx, &db, 0);
	entry_refresh(ctx.entry_win, &db.groups[0].entries[0], WGROUPS, 1, 0);
	head_refresh(&ctx);
	status_refresh(&ctx, &db);
	// Start handle events 
	while (1) {
		key = wgetch(stdscr);
		switch (key) {
		case KEY_RESIZE:
			xmax = getmaxx(stdscr);
			ymax = getmaxy(stdscr);

			resize_window(ctx.head_win, xmax, 1, 0, 0);
			resize_window(ctx.groups_win, xmax / 8, ymax - 2, 0, 1);
			resize_window(ctx.entries_win, xmax / 8, ymax - 2, xmax / 8, 1);
			resize_window(ctx.entry_win, xmax - (xmax / 4), ymax - 2, xmax / 4, 1);
			resize_window(ctx.status_win, xmax, 1, 0, ymax - 1);

			refresh();
			refresh_ctx(&ctx, &db);
			status_refresh(&ctx, &db);
			break;
		case KEY_LEFT:
			current = MAX(WGROUPS, current - 1);		
			break;
		case KEY_RIGHT:
			current = MIN(WENTRY, current + 1);		
			break;
		default:
			break;
		}

		if (current != ctx.current) {
			switch (ctx.current) {
			case WGROUPS:
				ctx.current = current;
				groups_loop(&ctx, &db, key);
				ctx.entry_sel = 0;
				break;
			case WENTRIES:
				ctx.current = current;
				process_entries(&ctx, &db, key);
				ctx.value_sel = 0;
				break;
			case WENTRY:
				ctx.current = current;
				process_entry(&ctx, &db, key);
				break;
			}
		}

		switch (current) {
		case WGROUPS:
			groups_loop(&ctx, &db, key);
			break;
		case WENTRIES:
			process_entries(&ctx, &db, key);
			break;
		case WENTRY:
			process_entry(&ctx, &db, key);
			break;
		}

		/* Global commands:
		 *	w - Write command
		 *	/ - Enter command mode
		 * */
		switch (key) {
		case 'w':
			if ((ret = write_db(&ctx, &db)))
				set_error(&ctx, "write db fail: %s", kdbx_strerror(ret));
			
			break;
		case '/':
			if (!process_cmd(&ctx, &db))
				refresh_ctx(&ctx, &db);

			break;
		case CTRL('c'):
			quit(&ctx, &db);
			break;
		}

		status_refresh(&ctx, &db);
	}

	// Securely frees the memory protecting data
	kdbx_free(&db);

	endwin();
	return EXIT_SUCCESS;
}

#endif
