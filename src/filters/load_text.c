/*
 *			GPAC - Multimedia Framework C SDK
 *
 *			Authors: Jean Le Feuvre
 *			Copyright (c) Telecom ParisTech 2000-2012
 *					All rights reserved
 *
 *  This file is part of GPAC / text import filter
 *
 *  GPAC is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  GPAC is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */



#include <gpac/filters.h>
#include <gpac/constants.h>
#include <gpac/utf.h>
#include <gpac/xml.h>
#include <gpac/token.h>
#include <gpac/color.h>
#include <gpac/internal/media_dev.h>
#include <gpac/internal/isomedia_dev.h>

typedef struct __txtin_ctx GF_TXTIn;

struct __txtin_ctx
{
	//opts
	u32 width, height, x, y, fontsize;
	s32 zorder;
	const char *fontname, *lang;
	Bool nodefbox, noflush, webvtt;
	u32 timescale;
	GF_Fraction fps;


	GF_FilterPid *ipid, *opid;
	const char *file_name;
	u32 fmt;

	Bool is_setup;

	GF_Err (*text_process)(GF_Filter *filter, GF_TXTIn *ctx);

	s32 unicode_type;

	FILE *src;

	GF_BitStream *bs_w;
	Bool first_samp;

	//state vars for srt
	u32 state, default_color;
	GF_TextSample *samp;
	u64 start, end, prev_end;
	u32 curLine;

	//WebVTT state
	GF_WebVTTParser *vttparser;

	//TTXT state
	GF_DOMParser *parser;
	u32 cur_child_idx, nb_children, last_desc_idx;
	GF_List *text_descs;
	Bool last_sample_empty;
	u64 last_sample_duration;

};


enum
{
	GF_TEXT_IMPORT_NONE = 0,
	GF_TEXT_IMPORT_SRT,
	GF_TEXT_IMPORT_SUB,
	GF_TEXT_IMPORT_TTXT,
	GF_TEXT_IMPORT_TEXML,
	GF_TEXT_IMPORT_WEBVTT,
	GF_TEXT_IMPORT_TTML,
	GF_TEXT_IMPORT_SWF_SVG,
};

#define REM_TRAIL_MARKS(__str, __sep) while (1) {	\
		u32 _len = (u32) strlen(__str);		\
		if (!_len) break;	\
		_len--;				\
		if (strchr(__sep, __str[_len])) __str[_len] = 0;	\
		else break;	\
	}	\
 

s32 gf_text_get_utf_type(FILE *in_src)
{
	u32 read;
	unsigned char BOM[5];
	read = (u32) fread(BOM, sizeof(char), 5, in_src);
	if ((s32) read < 1)
		return -1;

	if ((BOM[0]==0xFF) && (BOM[1]==0xFE)) {
		/*UTF32 not supported*/
		if (!BOM[2] && !BOM[3]) return -1;
		gf_fseek(in_src, 2, SEEK_SET);
		return 3;
	}
	if ((BOM[0]==0xFE) && (BOM[1]==0xFF)) {
		/*UTF32 not supported*/
		if (!BOM[2] && !BOM[3]) return -1;
		gf_fseek(in_src, 2, SEEK_SET);
		return 2;
	} else if ((BOM[0]==0xEF) && (BOM[1]==0xBB) && (BOM[2]==0xBF)) {
		gf_fseek(in_src, 3, SEEK_SET);
		return 1;
	}
	if (BOM[0]<0x80) {
		gf_fseek(in_src, 0, SEEK_SET);
		return 0;
	}
	return -1;
}

static GF_Err gf_text_guess_format(const char *filename, u32 *fmt)
{
	char szLine[2048];
	u32 val;
	s32 uni_type;
	FILE *test = gf_fopen(filename, "rb");
	if (!test) return GF_URL_ERROR;
	uni_type = gf_text_get_utf_type(test);

	if (uni_type>1) {
		const u16 *sptr;
		char szUTF[1024];
		u32 read = (u32) fread(szUTF, 1, 1023, test);
		if ((s32) read < 0) {
			gf_fclose(test);
			return GF_IO_ERR;
		}
		szUTF[read]=0;
		sptr = (u16*)szUTF;
		/*read = (u32) */gf_utf8_wcstombs(szLine, read, &sptr);
	} else {
		val = (u32) fread(szLine, 1, 1024, test);
		if ((s32) val<0) return GF_IO_ERR;
		
		szLine[val]=0;
	}
	REM_TRAIL_MARKS(szLine, "\r\n\t ")

	*fmt = GF_TEXT_IMPORT_NONE;
	if ((szLine[0]=='{') && strstr(szLine, "}{")) *fmt = GF_TEXT_IMPORT_SUB;
	else if (szLine[0] == '<') {
		char *ext = strrchr(filename, '.');
		if (!strnicmp(ext, ".ttxt", 5)) *fmt = GF_TEXT_IMPORT_TTXT;
		else if (!strnicmp(ext, ".ttml", 5)) *fmt = GF_TEXT_IMPORT_TTML;
		ext = strstr(szLine, "?>");
		if (ext) ext += 2;
		if (ext && !ext[0]) {
			if (!fgets(szLine, 2048, test))
				szLine[0] = '\0';
		}
		if (strstr(szLine, "x-quicktime-tx3g") || strstr(szLine, "text3GTrack")) *fmt = GF_TEXT_IMPORT_TEXML;
		else if (strstr(szLine, "TextStream")) *fmt = GF_TEXT_IMPORT_TTXT;
		else if (strstr(szLine, "tt")) *fmt = GF_TEXT_IMPORT_TTML;
	}
	else if (strstr(szLine, "WEBVTT") )
		*fmt = GF_TEXT_IMPORT_WEBVTT;
	else if (strstr(szLine, " --> ") )
		*fmt = GF_TEXT_IMPORT_SRT; /* might want to change the default to WebVTT */

	gf_fclose(test);
	return GF_OK;
}


#define TTXT_DEFAULT_WIDTH	400
#define TTXT_DEFAULT_HEIGHT	60
#define TTXT_DEFAULT_FONT_SIZE	18

void gf_text_get_video_size(GF_MediaImporter *import, u32 *width, u32 *height)
{
	u32 w, h, f_w, f_h, i;
	GF_ISOFile *dest = import->dest;

	if (import->text_track_width && import->text_track_height) {
		(*width) = import->text_track_width;
		(*height) = import->text_track_height;
		return;
	}

	f_w = f_h = 0;
	for (i=0; i<gf_isom_get_track_count(dest); i++) {
		switch (gf_isom_get_media_type(dest, i+1)) {
		case GF_ISOM_MEDIA_SCENE:
		case GF_ISOM_MEDIA_VISUAL:
			gf_isom_get_visual_info(dest, i+1, 1, &w, &h);
			if (w > f_w) f_w = w;
			if (h > f_h) f_h = h;
			gf_isom_get_track_layout_info(dest, i+1, &w, &h, NULL, NULL, NULL);
			if (w > f_w) f_w = w;
			if (h > f_h) f_h = h;
			break;
		}
	}
	(*width) = f_w ? f_w : TTXT_DEFAULT_WIDTH;
	(*height) = f_h ? f_h : TTXT_DEFAULT_HEIGHT;
}


void gf_text_import_set_language(GF_MediaImporter *import, u32 track)
{
	if (import->esd && import->esd->langDesc) {
		char lang[4];
		lang[0] = (import->esd->langDesc->langCode>>16) & 0xFF;
		lang[1] = (import->esd->langDesc->langCode>>8) & 0xFF;
		lang[2] = (import->esd->langDesc->langCode) & 0xFF;
		lang[3] = 0;
		gf_isom_set_media_language(import->dest, track, lang);
	}
}

char *gf_text_get_utf8_line(char *szLine, u32 lineSize, FILE *txt_in, s32 unicode_type)
{
	u32 i, j, len;
	char *sOK;
	char szLineConv[1024];
	unsigned short *sptr;

	memset(szLine, 0, sizeof(char)*lineSize);
	sOK = fgets(szLine, lineSize, txt_in);
	if (!sOK) return NULL;
	if (unicode_type<=1) {
		j=0;
		len = (u32) strlen(szLine);
		for (i=0; i<len; i++) {
			if (!unicode_type && (szLine[i] & 0x80)) {
				/*non UTF8 (likely some win-CP)*/
				if ((szLine[i+1] & 0xc0) != 0x80) {
					szLineConv[j] = 0xc0 | ( (szLine[i] >> 6) & 0x3 );
					j++;
					szLine[i] &= 0xbf;
				}
				/*UTF8 2 bytes char*/
				else if ( (szLine[i] & 0xe0) == 0xc0) {
					szLineConv[j] = szLine[i];
					i++;
					j++;
				}
				/*UTF8 3 bytes char*/
				else if ( (szLine[i] & 0xf0) == 0xe0) {
					szLineConv[j] = szLine[i];
					i++;
					j++;
					szLineConv[j] = szLine[i];
					i++;
					j++;
				}
				/*UTF8 4 bytes char*/
				else if ( (szLine[i] & 0xf8) == 0xf0) {
					szLineConv[j] = szLine[i];
					i++;
					j++;
					szLineConv[j] = szLine[i];
					i++;
					j++;
					szLineConv[j] = szLine[i];
					i++;
					j++;
				} else {
					i+=1;
					continue;
				}
			}
			szLineConv[j] = szLine[i];
			j++;
		}
		szLineConv[j] = 0;
		strcpy(szLine, szLineConv);
		return sOK;
	}

#ifdef GPAC_BIG_ENDIAN
	if (unicode_type==3) {
#else
	if (unicode_type==2) {
#endif
		i=0;
		while (1) {
			char c;
			if (!szLine[i] && !szLine[i+1]) break;
			c = szLine[i+1];
			szLine[i+1] = szLine[i];
			szLine[i] = c;
			i+=2;
		}
	}
	sptr = (u16 *)szLine;
	i = (u32) gf_utf8_wcstombs(szLineConv, 1024, (const unsigned short **) &sptr);
	szLineConv[i] = 0;
	strcpy(szLine, szLineConv);
	/*this is ugly indeed: since input is UTF16-LE, there are many chances the fgets never reads the \0 after a \n*/
	if (unicode_type==3) fgetc(txt_in);
	return sOK;
}


static GF_Err txtin_setup_srt(GF_Filter *filter, GF_TXTIn *ctx)
{
	GF_StyleRecord rec;
	u32 ID, OCR_ES_ID, dsi_len, file_size;
	char *dsi;
	GF_TextSampleDescriptor *sd;

	ctx->src = gf_fopen(ctx->file_name, "rt");
	if (!ctx->src) return GF_URL_ERROR;

	gf_fseek(ctx->src, 0, SEEK_END);
	file_size = gf_ftell(ctx->src);
	gf_fseek(ctx->src, 0, SEEK_SET);

	ctx->unicode_type = gf_text_get_utf_type(ctx->src);
	if (ctx->unicode_type<0) {
		gf_fclose(ctx->src);
		ctx->src = NULL;
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Unsupported SRT UTF encoding\n"));
		return GF_NOT_SUPPORTED;
	}

	if (!ctx->timescale) ctx->timescale = 1000;
	OCR_ES_ID = ID = 0;

	if (!ctx->opid) ctx->opid = gf_filter_pid_new(filter);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_TEXT) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_OTI, &PROP_UINT(GF_ISOM_SUBTYPE_TX3G) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_TIMESCALE, &PROP_UINT(ctx->timescale) );
	gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_SIZE, &PROP_UINT(file_size) );

	if (!ID) ID = 1;
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ID, &PROP_UINT(ID) );
	if (OCR_ES_ID) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CLOCK_ID, &PROP_UINT(OCR_ES_ID) );
	if (ctx->width) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx->width) );
	if (ctx->height) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx->height) );
	if (ctx->zorder) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ZORDER, &PROP_SINT(ctx->zorder) );
	if (ctx->lang) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_LANGUAGE, &PROP_STRING((char *) ctx->lang) );

#ifdef FILTER_FIXME
	/*setup track*/
	if (cfg) {
		char *firstFont = NULL;
		/*set track info*/
		/*and set sample descriptions*/
		count = gf_list_count(cfg->sample_descriptions);
		for (i=0; i<count; i++) {
			GF_TextSampleDescriptor *sd= (GF_TextSampleDescriptor *)gf_list_get(cfg->sample_descriptions, i);
			if (!sd->font_count) {
				sd->fonts = (GF_FontRecord*)gf_malloc(sizeof(GF_FontRecord));
				sd->font_count = 1;
				sd->fonts[0].fontID = 1;
				sd->fonts[0].fontName = gf_strdup("Serif");
			}
			if (!sd->default_style.fontID) sd->default_style.fontID = sd->fonts[0].fontID;
			if (!sd->default_style.font_size) sd->default_style.font_size = 16;
			if (!sd->default_style.text_color) sd->default_style.text_color = 0xFF000000;
			/*store attribs*/
			if (!i) rec = sd->default_style;

			gf_isom_new_text_description(import->dest, track, sd, NULL, NULL, &state);
			if (!firstFont) firstFont = sd->fonts[0].fontName;
		}
		gf_import_message(import, GF_OK, "Timed Text (SRT) import - text track %d x %d, font %s (size %d)", cfg->text_width, cfg->text_height, firstFont, rec.font_size);

		gf_odf_desc_del((GF_Descriptor *)cfg);
	}
#endif

	sd = (GF_TextSampleDescriptor*)gf_odf_desc_new(GF_ODF_TX3G_TAG);
	sd->fonts = (GF_FontRecord*)gf_malloc(sizeof(GF_FontRecord));
	sd->font_count = 1;
	sd->fonts[0].fontID = 1;
	sd->fonts[0].fontName = gf_strdup(ctx->fontname ? ctx->fontname : "Serif");
	sd->back_color = 0x00000000;	/*transparent*/
	sd->default_style.fontID = 1;
	sd->default_style.font_size = ctx->fontsize ? ctx->fontsize : TTXT_DEFAULT_FONT_SIZE;
	sd->default_style.text_color = 0xFFFFFFFF;	/*white*/
	sd->default_style.style_flags = 0;
	sd->horiz_justif = 1; /*center of scene*/
	sd->vert_justif = (s8) -1;	/*bottom of scene*/

	if (ctx->nodefbox) {
		sd->default_pos.top = sd->default_pos.left = sd->default_pos.right = sd->default_pos.bottom = 0;
	} else if ((sd->default_pos.bottom==sd->default_pos.top) || (sd->default_pos.right==sd->default_pos.left)) {
		sd->default_pos.left = ctx->x;
		sd->default_pos.top = ctx->y;
		sd->default_pos.right = ctx->width + sd->default_pos.left;
		sd->default_pos.bottom = ctx->height + sd->default_pos.top;
	}

	/*store attribs*/
	rec = sd->default_style;
	gf_odf_tx3g_write(sd, &dsi, &dsi_len);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, &PROP_DATA_NO_COPY(dsi, dsi_len) );

	gf_odf_desc_del((GF_Descriptor *)sd);

	ctx->default_color = rec.text_color;
	ctx->samp = gf_isom_new_text_sample();
	ctx->state = 0;
	ctx->end = ctx->prev_end = ctx->start = 0;
	ctx->first_samp = GF_TRUE;
	ctx->curLine = 0;
	return GF_OK;
}

static void txtin_process_send_text_sample(GF_TXTIn *ctx, GF_TextSample *txt_samp, u64 ts, u32 duration, Bool is_rap)
{
	GF_FilterPacket *dst_pck;
	char *pck_data;
	u32 size = gf_isom_text_sample_size(txt_samp);

	dst_pck = gf_filter_pck_new_alloc(ctx->opid, size, &pck_data);
	gf_bs_reassign_buffer(ctx->bs_w, pck_data, size);
	gf_isom_text_sample_write_bs(txt_samp, ctx->bs_w);

	gf_filter_pck_set_sap(dst_pck, is_rap ? GF_FILTER_SAP_1 : GF_FILTER_SAP_NONE);
	gf_filter_pck_set_cts(dst_pck, ts);
	gf_filter_pck_set_duration(dst_pck, duration);

	gf_filter_pck_send(dst_pck);
}

static GF_Err txtin_process_srt(GF_Filter *filter, GF_TXTIn *ctx)
{
	u32 i;
	GF_Err e;
	GF_StyleRecord rec;
	u32 sh, sm, ss, sms, eh, em, es, ems, txt_line, char_len, char_line, j, rem_styles;
	Bool set_start_char, set_end_char, rem_color;
	u32 line, len;
	char szLine[2048], szText[2048], *ptr;
	unsigned short uniLine[5000], uniText[5000], *sptr;

	if (!ctx->is_setup) {
		ctx->is_setup = GF_TRUE;
		return txtin_setup_srt(filter, ctx);
	}
	if (!ctx->opid) return GF_NOT_SUPPORTED;

	e = GF_OK;
	txt_line = 0;
	set_start_char = set_end_char = GF_FALSE;
	char_len = 0;

	while (1) {
		char *sOK = gf_text_get_utf8_line(szLine, 2048, ctx->src, ctx->unicode_type);

		if (sOK) REM_TRAIL_MARKS(szLine, "\r\n\t ")
			if (!sOK || !strlen(szLine)) {
				rec.style_flags = 0;
				rec.startCharOffset = rec.endCharOffset = 0;
				if (txt_line) {
					if (ctx->prev_end && (ctx->start != ctx->prev_end) && (ctx->state<=2)) {
						GF_TextSample * empty_samp = gf_isom_new_text_sample();
						txtin_process_send_text_sample(ctx, empty_samp, (u64) ((ctx->timescale * ctx->prev_end)/1000), (u64) (ctx->timescale * (ctx->start - ctx->prev_end) / 1000), GF_TRUE );
						gf_isom_delete_text_sample(empty_samp);
					}

					if (ctx->state<=2) {
						txtin_process_send_text_sample(ctx, ctx->samp,  (u64) ((ctx->timescale * ctx->start)/1000), (u64) (ctx->timescale * (ctx->end -  ctx->start) / 1000), GF_TRUE);
						ctx->prev_end = ctx->end;
					}
					txt_line = 0;
					char_len = 0;
					set_start_char = set_end_char = GF_FALSE;
					rec.startCharOffset = rec.endCharOffset = 0;
					gf_isom_text_reset(ctx->samp);

					gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_BYTES, &PROP_UINT( gf_ftell(ctx->src )) );
				}
				ctx->state = 0;
				if (!sOK) break;
				continue;
			}

		switch (ctx->state) {
		case 0:
			if (sscanf(szLine, "%u", &line) != 1) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Bad SRT formatting - expecting number got \"%s\"", szLine));
				break;
			}
			if (line != ctx->curLine + 1) {
				GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Corrupted SRT frame %d after frame %d", line, ctx->curLine));
			}
			ctx->curLine = line;
			ctx->state = 1;
			break;
		case 1:
			if (sscanf(szLine, "%u:%u:%u,%u --> %u:%u:%u,%u", &sh, &sm, &ss, &sms, &eh, &em, &es, &ems) != 8) {
				sh = eh = 0;
				if (sscanf(szLine, "%u:%u,%u --> %u:%u,%u", &sm, &ss, &sms, &em, &es, &ems) != 6) {
					GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Error scanning SRT frame %d timing", ctx->curLine));
				    ctx->state = 0;
					break;
				}
			}
			ctx->start = (3600*sh + 60*sm + ss)*1000 + sms;
			if (ctx->start < ctx->end) {
				GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Overlapping SRT frame %d - starts "LLD" ms is before end of previous one "LLD" ms - adjusting time stamps", ctx->curLine, ctx->start, ctx->end));
				ctx->start = ctx->end;
			}

			ctx->end = (3600*eh + 60*em + es)*1000 + ems;
			/*make stream start at 0 by inserting a fake AU*/
			if (ctx->first_samp && (ctx->start > 0)) {
				txtin_process_send_text_sample(ctx, ctx->samp, 0, (u64) (ctx->timescale * ctx->start / 1000), GF_TRUE);
			}
			rec.style_flags = 0;
			ctx->state = 2;
			if (ctx->end <= ctx->prev_end) {
				GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Overlapping SRT frame %d end "LLD" is at or before previous end "LLD" - removing", ctx->curLine, ctx->end, ctx->prev_end));
				ctx->start = ctx->end;
				ctx->state = 3;
			}
			break;

		default:
			/*reset only when text is present*/
			ctx->first_samp = GF_FALSE;

			/*go to line*/
			if (txt_line) {
				gf_isom_text_add_text(ctx->samp, "\n", 1);
				char_len += 1;
			}

			ptr = (char *) szLine;
			{
				size_t _len = gf_utf8_mbstowcs(uniLine, 5000, (const char **) &ptr);
				if (_len == (size_t) -1) {
					GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Invalid UTF data (line %d)", ctx->curLine));
					ctx->state = 0;
				}
				len = (u32) _len;
			}
			i=j=0;
			rem_styles = 0;
			rem_color = 0;
			while (i<len) {
				u32 font_style = 0;
				u32 style_nb_chars = 0;
				u32 style_def_type = 0;

				if ( (uniLine[i]=='<') && (uniLine[i+2]=='>')) {
					style_nb_chars = 3;
					style_def_type = 1;
				}
				else if ( (uniLine[i]=='<') && (uniLine[i+1]=='/') && (uniLine[i+3]=='>')) {
					style_def_type = 2;
					style_nb_chars = 4;
				}
				else if (uniLine[i]=='<')  {
					const unsigned short* src = uniLine + i;
					size_t alen = gf_utf8_wcstombs(szLine, 2048, (const unsigned short**) & src);
					szLine[alen] = 0;
					strlwr(szLine);
					if (!strncmp(szLine, "<font ", 6) ) {
						char *a_sep = strstr(szLine, "color");
						if (a_sep) a_sep = strchr(a_sep, '"');
						if (a_sep) {
							char *e_sep = strchr(a_sep+1, '"');
							if (e_sep) {
								e_sep[0] = 0;
								font_style = gf_color_parse(a_sep+1);
								e_sep[0] = '"';
								e_sep = strchr(e_sep+1, '>');
								if (e_sep) {
									style_nb_chars = (u32) (1 + e_sep - szLine);
									style_def_type = 1;
								}
							}

						}
					}
					else if (!strncmp(szLine, "</font>", 7) ) {
						style_nb_chars = 7;
						style_def_type = 2;
						font_style = 0xFFFFFFFF;
					}
					//skip unknown
					else {
						char *a_sep = strstr(szLine, ">");
						if (a_sep) {
							style_nb_chars = (u32) (a_sep - szLine);
							i += style_nb_chars;
							continue;
						}
					}

				}

				/*start of new style*/
				if (style_def_type==1)  {
					/*store prev style*/
					if (set_end_char) {
						assert(set_start_char);
						gf_isom_text_add_style(ctx->samp, &rec);
						set_end_char = set_start_char = GF_FALSE;
						rec.style_flags &= ~rem_styles;
						rem_styles = 0;
						if (rem_color) {
							rec.text_color = ctx->default_color;
							rem_color = 0;
						}
					}
					if (set_start_char && (rec.startCharOffset != j)) {
						rec.endCharOffset = char_len + j;
						if (rec.style_flags) gf_isom_text_add_style(ctx->samp, &rec);
					}
					switch (uniLine[i+1]) {
					case 'b':
					case 'B':
						rec.style_flags |= GF_TXT_STYLE_BOLD;
						set_start_char = GF_TRUE;
						rec.startCharOffset = char_len + j;
						break;
					case 'i':
					case 'I':
						rec.style_flags |= GF_TXT_STYLE_ITALIC;
						set_start_char = GF_TRUE;
						rec.startCharOffset = char_len + j;
						break;
					case 'u':
					case 'U':
						rec.style_flags |= GF_TXT_STYLE_UNDERLINED;
						set_start_char = GF_TRUE;
						rec.startCharOffset = char_len + j;
						break;
					case 'f':
					case 'F':
						if (font_style) {
							rec.text_color = font_style;
							set_start_char = GF_TRUE;
							rec.startCharOffset = char_len + j;
						}
						break;
					}
					i += style_nb_chars;
					continue;
				}

				/*end of prev style*/
				if (style_def_type==2)  {
					switch (uniLine[i+2]) {
					case 'b':
					case 'B':
						rem_styles |= GF_TXT_STYLE_BOLD;
						set_end_char = GF_TRUE;
						rec.endCharOffset = char_len + j;
						break;
					case 'i':
					case 'I':
						rem_styles |= GF_TXT_STYLE_ITALIC;
						set_end_char = GF_TRUE;
						rec.endCharOffset = char_len + j;
						break;
					case 'u':
					case 'U':
						rem_styles |= GF_TXT_STYLE_UNDERLINED;
						set_end_char = GF_TRUE;
						rec.endCharOffset = char_len + j;
						break;
					case 'f':
					case 'F':
						if (font_style) {
							rem_color = 1;
							set_end_char = GF_TRUE;
							rec.endCharOffset = char_len + j;
						}
					}
					i+=style_nb_chars;
					continue;
				}
				/*store style*/
				if (set_end_char) {
					gf_isom_text_add_style(ctx->samp, &rec);
					set_end_char = GF_FALSE;
					set_start_char = GF_TRUE;
					rec.startCharOffset = char_len + j;
					rec.style_flags &= ~rem_styles;
					rem_styles = 0;
					rec.text_color = ctx->default_color;
					rem_color = 0;
				}

				uniText[j] = uniLine[i];
				j++;
				i++;
			}
			/*store last style*/
			if (set_end_char) {
				gf_isom_text_add_style(ctx->samp, &rec);
				set_end_char = GF_FALSE;
				set_start_char = GF_TRUE;
				rec.startCharOffset = char_len + j;
				rec.style_flags &= ~rem_styles;
			}

			char_line = j;
			uniText[j] = 0;

			sptr = (u16 *) uniText;
			len = (u32) gf_utf8_wcstombs(szText, 5000, (const u16 **) &sptr);

			gf_isom_text_add_text(ctx->samp, szText, len);
			char_len += char_line;
			txt_line ++;
			break;
		}

		if (gf_filter_pid_would_block(ctx->opid))
			return GF_OK;
	}

	/*final flush*/	
	if (ctx->end && ! ctx->noflush) {
		gf_isom_text_reset(ctx->samp);
		txtin_process_send_text_sample(ctx, ctx->samp, (u64) ((ctx->timescale * ctx->end)/1000), 0, GF_TRUE);
		ctx->end = 0;
	}
	gf_isom_text_reset(ctx->samp);

	return GF_EOS;
}

/* Structure used to pass importer and track data to the parsers without exposing the GF_MediaImporter structure
   used by WebVTT and Flash->SVG */
typedef struct {
	GF_MediaImporter *import;
	u32 timescale;
	u32 track;
	u32 descriptionIndex;
} GF_ISOFlusher;

#ifndef GPAC_DISABLE_VTT

static GF_Err gf_webvtt_import_report(void *user, GF_Err e, char *message, const char *line)
{
	GF_LOG(e ? GF_LOG_WARNING : GF_LOG_INFO, GF_LOG_AUTHOR, ("[TXTIn] WebVTT line %s: %s\n", line, message) );
	return e;
}

static void gf_webvtt_import_header(void *user, const char *config)
{
	GF_TXTIn *ctx = (GF_TXTIn *)user;
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, &PROP_DATA((char *) config, (1+strlen(config)) ) );
}

static void gf_webvtt_flush_sample(void *user, GF_WebVTTSample *samp)
{
	u64 start, end;
	GF_TXTIn *ctx = (GF_TXTIn *)user;
	GF_ISOSample *s = gf_isom_webvtt_to_sample(samp);
	if (s) {
		GF_FilterPacket *pck;
		char *pck_data;
		start = gf_webvtt_sample_get_start(samp);
		end = gf_webvtt_sample_get_end(samp);

		pck = gf_filter_pck_new_alloc(ctx->opid, s->dataLength, &pck_data);
		gf_filter_pck_set_cts(pck, (u64) (ctx->timescale * start / 1000) );
		gf_filter_pck_set_sap(pck, GF_FILTER_SAP_1);


		if (end && (end>=start) ) {
			gf_filter_pck_set_duration(pck, (u64) (ctx->timescale * (end-start) / 1000) );
		}
		gf_filter_pck_send(pck);

		gf_isom_sample_del(&s);
	}
	gf_webvtt_sample_del(samp);

	gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_BYTES, &PROP_UINT( gf_ftell(ctx->src )) );

	if (gf_filter_pid_would_block(ctx->opid))
		gf_webvtt_parser_suspend(ctx->vttparser);

}

static GF_Err txtin_webvtt_setup(GF_Filter *filter, GF_TXTIn *ctx)
{
	GF_Err e;
	u32 ID, OCR_ES_ID, file_size, w, h;
	Bool is_srt;
	char *ext;

	ctx->src = gf_fopen(ctx->file_name, "rt");
	if (!ctx->src) return GF_URL_ERROR;

	gf_fseek(ctx->src, 0, SEEK_END);
	file_size = gf_ftell(ctx->src);
	gf_fseek(ctx->src, 0, SEEK_SET);

	ctx->unicode_type = gf_text_get_utf_type(ctx->src);
	if (ctx->unicode_type<0) {
		gf_fclose(ctx->src);
		ctx->src = NULL;
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Unsupported SRT UTF encoding\n"));
		return GF_NOT_SUPPORTED;
	}
	ext = strrchr(ctx->file_name, '.');
	is_srt = (ext && !strnicmp(ext, ".srt", 4)) ? GF_TRUE : GF_FALSE;


	if (!ctx->timescale) ctx->timescale = 1000;
	OCR_ES_ID = ID = 0;

	if (!ctx->opid) ctx->opid = gf_filter_pid_new(filter);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_TEXT) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_OTI, &PROP_UINT(GF_ISOM_SUBTYPE_WVTT) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_TIMESCALE, &PROP_UINT(ctx->timescale) );
	gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_SIZE, &PROP_UINT(file_size) );

	w = ctx->width ? ctx->width : TTXT_DEFAULT_WIDTH;
	h = ctx->height ? ctx->height : TTXT_DEFAULT_HEIGHT;
	if (!ID) ID = 1;
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ID, &PROP_UINT(ID) );
	if (OCR_ES_ID) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CLOCK_ID, &PROP_UINT(OCR_ES_ID) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(w) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(h) );
	if (ctx->zorder) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ZORDER, &PROP_SINT(ctx->zorder) );
	if (ctx->lang) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_LANGUAGE, &PROP_STRING((char *) ctx->lang) );

	ctx->vttparser = gf_webvtt_parser_new();

	e = gf_webvtt_parser_init(ctx->vttparser, ctx->src, ctx->unicode_type, is_srt, ctx, gf_webvtt_import_report, gf_webvtt_flush_sample, gf_webvtt_import_header);
	if (e != GF_OK) {
		gf_webvtt_parser_del(ctx->vttparser);
		ctx->vttparser = NULL;
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] WebVTT parser init error %s\n", gf_error_to_string(e) ));
	}
	return e;
}

static GF_Err txtin_process_webvtt(GF_Filter *filter, GF_TXTIn *ctx)
{
	GF_Err e;

	if (!ctx->is_setup) {
		ctx->is_setup = GF_TRUE;
		return txtin_webvtt_setup(filter, ctx);
	}
	if (!ctx->vttparser) return GF_NOT_SUPPORTED;

	e = gf_webvtt_parser_parse(ctx->vttparser);

	if (e < GF_OK) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] WebVTT process error %s\n", gf_error_to_string(e) ));
	}

	/*do not add any empty sample at the end since it modifies track duration and is not needed - it is the player job
	to figure out when to stop displaying the last text sample
	However update the last sample duration*/
//	gf_isom_set_last_sample_duration(import->dest, track, (u32) gf_webvtt_parser_last_duration(ctx->vttparser));
	
	return e;
}

#endif /*GPAC_DISABLE_VTT*/

static char *ttxt_parse_string(char *str, Bool strip_lines)
{
	u32 i=0;
	u32 k=0;
	u32 len = (u32) strlen(str);
	u32 state = 0;

	if (!strip_lines) {
		for (i=0; i<len; i++) {
			if ((str[i] == '\r') && (str[i+1] == '\n')) {
				i++;
			}
			str[k] = str[i];
			k++;
		}
		str[k]=0;
		return str;
	}

	if (str[0]!='\'') return str;
	for (i=0; i<len; i++) {
		if (str[i] == '\'') {

			if (!state) {
				if (k) {
					str[k]='\n';
					k++;
				}
				state = !state;
			} else if (state) {
				if ( (i+1==len) ||
				        ((str[i+1]==' ') || (str[i+1]=='\n') || (str[i+1]=='\r') || (str[i+1]=='\t') || (str[i+1]=='\''))
				   ) {
					state = !state;
				} else {
					str[k] = str[i];
					k++;
				}
			}
		} else if (state) {
			str[k] = str[i];
			k++;
		}
	}
	str[k]=0;
	return str;
}

static void ttml_import_progress(void *cbk, u64 cur_samp, u64 count)
{
	gf_set_progress("TTML Loading", cur_samp, count);
}

static void gf_text_import_ebu_ttd_remove_samples(GF_XMLNode *root, GF_XMLNode **sample_list_node)
{
	u32 idx = 0, body_num = 0;
	GF_XMLNode *node = NULL;
	*sample_list_node = NULL;
	while ( (node = (GF_XMLNode*)gf_list_enum(root->content, &idx))) {
		if (!strcmp(node->name, "body")) {
			GF_XMLNode *body_node;
			u32 body_idx = 0;
			while ( (body_node = (GF_XMLNode*)gf_list_enum(node->content, &body_idx))) {
				if (!strcmp(body_node->name, "div")) {
					*sample_list_node = body_node;
					body_num = gf_list_count(body_node->content);
					while (body_num--) {
						GF_XMLNode *content_node = (GF_XMLNode*)gf_list_get(body_node->content, 0);
						assert(gf_list_find(body_node->content, content_node) == 0);
						gf_list_rem(body_node->content, 0);
						gf_xml_dom_node_del(content_node);
					}
					return;
				}
			}
		}
	}
}

#define TTML_NAMESPACE "http://www.w3.org/ns/ttml"
static GF_Err gf_text_import_ebu_ttd(GF_MediaImporter *import, GF_DOMParser *parser, GF_XMLNode *root)
{
	GF_Err e, e_opt;
	u32 i, track, ID, desc_idx, nb_samples, nb_children;
	u64 last_sample_duration, last_sample_end;
	GF_XMLAttribute *att;
	GF_XMLNode *node, *root_working_copy, *sample_list_node;
	GF_DOMParser *parser_working_copy;
	char *samp_text;
	Bool has_body;

	samp_text = NULL;
	root_working_copy = NULL;
	parser_working_copy = NULL;

	/*setup track in 3GP format directly (no ES desc)*/
	ID = (import->esd) ? import->esd->ESID : 0;
	track = gf_isom_new_track(import->dest, ID, GF_ISOM_MEDIA_MPEG_SUBT, 1000);
	if (!track) {
		e = gf_isom_last_error(import->dest);
		goto exit;
	}
	gf_isom_set_track_enabled(import->dest, track, 1);

	/*some MPEG-4 setup*/
	if (import->esd) {
		if (!import->esd->ESID) import->esd->ESID = gf_isom_get_track_id(import->dest, track);
		if (!import->esd->decoderConfig) import->esd->decoderConfig = (GF_DecoderConfig *) gf_odf_desc_new(GF_ODF_DCD_TAG);
		if (!import->esd->slConfig) import->esd->slConfig = (GF_SLConfig *) gf_odf_desc_new(GF_ODF_SLC_TAG);
		import->esd->slConfig->timestampResolution = 1000;
		import->esd->decoderConfig->streamType = GF_STREAM_TEXT;
		import->esd->decoderConfig->objectTypeIndication = GPAC_OTI_TEXT_MPEG4;
		if (import->esd->OCRESID) gf_isom_set_track_reference(import->dest, track, GF_ISOM_REF_OCR, import->esd->OCRESID);
	}

	gf_import_message(import, GF_OK, "TTML EBU-TTD Import");

	/*** root (including language) ***/
	i=0;
	while ( (att = (GF_XMLAttribute *)gf_list_enum(root->attributes, &i))) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_PARSER, ("Found root attribute name %s, value %s\n", att->name, att->value));

		if (!strcmp(att->name, "xmlns")) {
			if (strcmp(att->value, TTML_NAMESPACE)) {
				e = gf_import_message(import, GF_BAD_PARAM, "Found invalid EBU-TTD root attribute name %s, value %s (shall be \"%s\")\n", att->name, att->value, TTML_NAMESPACE);
				goto exit;
			}
		} else if (!strcmp(att->name, "xml:lang")) {
			if (import->esd && !import->esd->langDesc) {
				char *lang;
				lang = gf_strdup(att->value);
				import->esd->langDesc = (GF_Language *) gf_odf_desc_new(GF_ODF_LANG_TAG);
				gf_isom_set_media_language(import->dest, track, lang);
			}
		}
	}

	/*** style ***/
#if 0
	{
		Bool has_styling, has_style;
		GF_TextSampleDescriptor *sd;
		has_styling = GF_FALSE;
		has_style = GF_FALSE;
		sd = (GF_TextSampleDescriptor*)gf_odf_desc_new(GF_ODF_TX3G_TAG);
		i=0;
		while ( (node = (GF_XMLNode*)gf_list_enum(root->content, &i))) {
			if (node->type) {
				continue;
			} else if (gf_xml_get_element_check_namespace(node, "head", root->ns) == GF_OK) {
				GF_XMLNode *head_node;
				u32 head_idx = 0;
				while ( (head_node = (GF_XMLNode*)gf_list_enum(node->content, &head_idx))) {
					if (gf_xml_get_element_check_namespace(head_node, "styling", root->ns) == GF_OK) {
						GF_XMLNode *styling_node;
						u32 styling_idx;
						if (has_styling) {
							e = gf_import_message(import, GF_BAD_PARAM, "[TTML EBU-TTD] duplicated \"styling\" element. Abort.\n");
							goto exit;
						}
						has_styling = GF_TRUE;

						styling_idx = 0;
						while ( (styling_node = (GF_XMLNode*)gf_list_enum(head_node->content, &styling_idx))) {
							if (gf_xml_get_element_check_namespace(styling_node, "style", root->ns) == GF_OK) {
								GF_XMLAttribute *p_att;
								u32 style_idx = 0;
								while ( (p_att = (GF_XMLAttribute*)gf_list_enum(styling_node->attributes, &style_idx))) {
									if (!strcmp(p_att->name, "tts:direction")) {
									} else if (!strcmp(p_att->name, "tts:fontFamily")) {
										sd->fonts = (GF_FontRecord*)gf_malloc(sizeof(GF_FontRecord));
										sd->font_count = 1;
										sd->fonts[0].fontID = 1;
										sd->fonts[0].fontName = gf_strdup(p_att->value);
									} else if (!strcmp(p_att->name, "tts:backgroundColor")) {
										GF_LOG(GF_LOG_INFO, GF_LOG_PARSER, ("EBU-TTD style attribute \"%s\" ignored.\n", p_att->name));
										//sd->back_color = ;
									} else {
										if ( !strcmp(p_att->name, "tts:fontSize")
										        || !strcmp(p_att->name, "tts:lineHeight")
										        || !strcmp(p_att->name, "tts:textAlign")
										        || !strcmp(p_att->name, "tts:color")
										        || !strcmp(p_att->name, "tts:fontStyle")
										        || !strcmp(p_att->name, "tts:fontWeight")
										        || !strcmp(p_att->name, "tts:textDecoration")
										        || !strcmp(p_att->name, "tts:unicodeBidi")
										        || !strcmp(p_att->name, "tts:wrapOption")
										        || !strcmp(p_att->name, "tts:multiRowAlign")
										        || !strcmp(p_att->name, "tts:linePadding")) {
											GF_LOG(GF_LOG_INFO, GF_LOG_PARSER, ("EBU-TTD style attribute \"%s\" ignored.\n", p_att->name));
										} else {
											GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("EBU-TTD unknown style attribute: \"%s\". Ignoring.\n", p_att->name));
										}
									}
								}
								break; //TODO: we only take care of the first style
							}
						}
					}
				}
			}
		}
		if (!has_styling) {
			e = gf_import_message(import, GF_BAD_PARAM, "[TTML EBU-TTD] missing \"styling\" element. Abort.\n");
			goto exit;
		}
		if (!has_style) {
			e = gf_import_message(import, GF_BAD_PARAM, "[TTML EBU-TTD] missing \"style\" element. Abort.\n");
			goto exit;
		}
		e = gf_isom_new_text_description(import->dest, track, sd, NULL, NULL, &desc_idx);
		gf_odf_desc_del((GF_Descriptor*)sd);
	}
#else
	e = gf_isom_new_xml_subtitle_description(import->dest, track, TTML_NAMESPACE, NULL, NULL, &desc_idx);
#endif
	if (e != GF_OK) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML EBU-TTD] incorrect sample description. Abort.\n"));
		e = gf_isom_last_error(import->dest);
		goto exit;
	}

	/*** body ***/
	parser_working_copy = gf_xml_dom_new();
	e = gf_xml_dom_parse(parser_working_copy, import->in_name, NULL, NULL);
	assert (e == GF_OK);
	root_working_copy = gf_xml_dom_get_root(parser_working_copy);
	assert(root_working_copy);
	last_sample_duration = 0;
	last_sample_end = 0;
	nb_samples = 0;
	nb_children = gf_list_count(root->content);
	has_body = GF_FALSE;
	i=0;
	while ( (node = (GF_XMLNode*)gf_list_enum(root->content, &i))) {
		if (node->type) {
			nb_children--;
			continue;
		}

		e_opt = gf_xml_get_element_check_namespace(node, "body", root->ns);
		if (e_opt == GF_BAD_PARAM) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML EBU-TTD] ignored \"%s\" node, check your namespaces\n", node->name));
		} else if (e_opt == GF_OK) {
			GF_XMLNode *body_node;
			u32 body_idx = 0;

			if (has_body) {
				e = gf_import_message(import, GF_BAD_PARAM, "[TTML EBU-TTD] duplicated \"body\" element. Abort.\n");
				goto exit;
			}
			has_body = GF_TRUE;

			/*remove all the entries from the working copy, we'll add samples one to one to create full XML samples*/
			gf_text_import_ebu_ttd_remove_samples(root_working_copy, &sample_list_node);

			while ( (body_node = (GF_XMLNode*)gf_list_enum(node->content, &body_idx))) {
				e_opt = gf_xml_get_element_check_namespace(body_node, "div", root->ns);
				if (e_opt == GF_BAD_PARAM) {
					GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML EBU-TTD] ignored \"%s\" node, check your namespaces\n", node->name));
				} else if (e_opt == GF_OK) {
					GF_XMLNode *div_node;
					u32 div_idx = 0, nb_p_found = 0;
					while ( (div_node = (GF_XMLNode*)gf_list_enum(body_node->content, &div_idx))) {
						e_opt = gf_xml_get_element_check_namespace(div_node, "p", root->ns);
						if (e_opt != GF_OK) {
							GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML] ignored \"%s\" node, check your namespaces\n", node->name));
						} else if (e_opt == GF_OK) {
							GF_XMLNode *p_node;
							GF_XMLAttribute *p_att;
							u32 p_idx = 0, h, m, s, ms;
							s64 ts_begin = -1, ts_end = -1;

							//sample is either in the <p> ...
							while ( (p_att = (GF_XMLAttribute*)gf_list_enum(div_node->attributes, &p_idx))) {
								if (!p_att) continue;
								
								if (!strcmp(p_att->name, "begin")) {
									if (ts_begin != -1) {
										e = gf_import_message(import, GF_BAD_PARAM, "[TTML] duplicated \"begin\" attribute. Abort.\n");
										goto exit;
									}
									if (sscanf(p_att->value, "%u:%u:%u.%u", &h, &m, &s, &ms) == 4) {
										ts_begin = (h*3600 + m*60+s)*1000+ms;
									} else if (sscanf(p_att->value, "%u:%u:%u", &h, &m, &s) == 3) {
										ts_begin = (h*3600 + m*60+s)*1000;
									}
								} else if (!strcmp(p_att->name, "end")) {
									if (ts_end != -1) {
										e = gf_import_message(import, GF_BAD_PARAM, "[TTML] duplicated \"end\" attribute. Abort.\n");
										goto exit;
									}
									if (sscanf(p_att->value, "%u:%u:%u.%u", &h, &m, &s, &ms) == 4) {
										ts_end = (h*3600 + m*60+s)*1000+ms;
									} else if (sscanf(p_att->value, "%u:%u:%u", &h, &m, &s) == 3) {
										ts_end = (h*3600 + m*60+s)*1000;
									}
								}
								if ((ts_begin != -1) && (ts_end != -1) && !samp_text && sample_list_node) {
									e = gf_xml_dom_append_child(sample_list_node, div_node);
									assert(e == GF_OK);
									assert(!samp_text);
									samp_text = gf_xml_dom_serialize((GF_XMLNode*)root_working_copy, GF_FALSE);
									e = gf_xml_dom_rem_child(sample_list_node, div_node);
									assert(e == GF_OK);
								}
							}

							//or under a <span>
							p_idx = 0;
							while ( (p_node = (GF_XMLNode*)gf_list_enum(div_node->content, &p_idx))) {
								e_opt = gf_xml_get_element_check_namespace(p_node, "span", root->ns);
								if (e_opt == GF_BAD_PARAM) {
									GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML] ignored \"%s\" node, check your namespaces\n", node->name));
								} else if (e_opt == GF_OK) {
									u32 span_idx = 0;
									GF_XMLAttribute *span_att;
									while ( (span_att = (GF_XMLAttribute*)gf_list_enum(p_node->attributes, &span_idx))) {
										if (!span_att) continue;
									
										if (!strcmp(span_att->name, "begin")) {
											if (ts_begin != -1) {
												e = gf_import_message(import, GF_BAD_PARAM, "[TTML] duplicated \"begin\" attribute under <span>. Abort.\n");
												goto exit;
											}
											if (sscanf(span_att->value, "%u:%u:%u.%u", &h, &m, &s, &ms) == 4) {
												ts_begin = (h*3600 + m*60+s)*1000+ms;
											} else if (sscanf(span_att->value, "%u:%u:%u", &h, &m, &s) == 3) {
												ts_begin = (h*3600 + m*60+s)*1000;
											}
										} else if (!strcmp(span_att->name, "end")) {
											if (ts_end != -1) {
												e = gf_import_message(import, GF_BAD_PARAM, "[TTML] duplicated \"end\" attribute under <span>. Abort.\n");
												goto exit;
											}
											if (sscanf(span_att->value, "%u:%u:%u.%u", &h, &m, &s, &ms) == 4) {
												ts_end = (h*3600 + m*60+s)*1000+ms;
											} else if (sscanf(span_att->value, "%u:%u:%u", &h, &m, &s) == 3) {
												ts_end = (h*3600 + m*60+s)*1000;
											}
										}
										if ((ts_begin != -1) && (ts_end != -1) && !samp_text && sample_list_node) {
											if (samp_text) {
												e = gf_import_message(import, GF_BAD_PARAM, "[TTML] duplicated sample text under <span>. Abort.\n");
												goto exit;
											}

											/*append the sample*/
											e = gf_xml_dom_append_child(sample_list_node, div_node);
											assert(e == GF_OK);
											assert(!samp_text);
											samp_text = gf_xml_dom_serialize((GF_XMLNode*)root_working_copy, GF_FALSE);
											e = gf_xml_dom_rem_child(sample_list_node, div_node);
											assert(e == GF_OK);
										}
									}
								}
							}

							if ((ts_begin != -1) && (ts_end != -1) && samp_text) {
								GF_ISOSample *s;
								GF_GenericSubtitleSample *samp;
								u32 len;
								char *str;

								if (ts_end < ts_begin) {
									e = gf_import_message(import, GF_BAD_PARAM, "[TTML] invalid timings: \"begin\"="LLD" , \"end\"="LLD". Abort.\n", ts_begin, ts_end);
									goto exit;
								}

								if (ts_begin < (s64)last_sample_end) {
									e = gf_import_message(import, GF_BAD_PARAM, "[TTML] timing overlapping not supported: \"begin\" is "LLD" , last \"end\" was "LLD". Abort.\n", ts_begin, last_sample_end);
									goto exit;
								}

								str = ttxt_parse_string(samp_text, GF_TRUE);
								len = (u32) strlen(str);
								samp = gf_isom_new_xml_subtitle_sample();
								/*each sample consists of a full valid XML file*/
								e = gf_isom_xml_subtitle_sample_add_text(samp, str, len);
								if (e) goto exit;
								gf_free(samp_text);
								samp_text = NULL;

								s = gf_isom_xml_subtitle_to_sample(samp);
								gf_isom_delete_xml_subtitle_sample(samp);
								if (!nb_samples) {
									s->DTS = 0; /*in MP4 we must start at T=0*/
									last_sample_duration = ts_end;
								} else {
									s->DTS = ts_begin;
									last_sample_duration = ts_end - ts_begin;
								}
								last_sample_end = ts_end;
								GF_LOG(GF_LOG_DEBUG, GF_LOG_PARSER, ("ts_begin="LLD", ts_end="LLD", last_sample_duration="LLU" (real duration: "LLU"), last_sample_end="LLU"\n", ts_begin, ts_end, ts_end - last_sample_end, last_sample_duration, last_sample_end));

								e = gf_isom_add_sample(import->dest, track, desc_idx, s);
								if (e) goto exit;
								gf_isom_sample_del(&s);
								nb_samples++;

								nb_p_found++;
								gf_set_progress("Importing TTML", nb_samples, nb_children);
								if (import->duration && (ts_end > import->duration))
									break;
							} else {
								GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML] incomplete sample (begin="LLD", end="LLD", text=\"%s\"). Skip.\n", ts_begin, ts_end, samp_text ? samp_text : "NULL"));
							}
						}
					}

					if (!nb_p_found) {
						GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML EBU-TTD] \"%s\" div node has no <p> elements. Aborting.\n", node->name));
						goto exit;
					}
				}
			}
		}
	}
	if (!has_body) {
		e = gf_import_message(import, GF_BAD_PARAM, "[TTML EBU-TTD] missing \"body\" element. Abort.\n");
		goto exit;
	}
	GF_LOG(GF_LOG_DEBUG, GF_LOG_PARSER, ("last_sample_duration="LLU", last_sample_end="LLU"\n", last_sample_duration, last_sample_end));
	gf_isom_set_last_sample_duration(import->dest, track, (u32) last_sample_duration);
	gf_set_progress("Importing TTML EBU-TTD", nb_samples, nb_samples);

exit:
	gf_free(samp_text);
	gf_xml_dom_del(parser_working_copy);
	if (!gf_isom_get_sample_count(import->dest, track)) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TTML EBU-TTD] No sample imported. Might be an error. Check your content.\n"));
	}
	return e;
}

static GF_Err gf_text_import_ttml(GF_MediaImporter *import)
{
	GF_Err e;
	GF_DOMParser *parser;
	GF_XMLNode *root;

	if (import->flags == GF_IMPORT_PROBE_ONLY)
		return GF_OK;

	parser = gf_xml_dom_new();
	e = gf_xml_dom_parse(parser, import->in_name, ttml_import_progress, import);
	if (e) {
		gf_import_message(import, e, "Error parsing TTML file: Line %d - %s. Abort.", gf_xml_dom_get_line(parser), gf_xml_dom_get_error(parser));
		gf_xml_dom_del(parser);
		return e;
	}
	root = gf_xml_dom_get_root(parser);
	if (!root) {
		gf_import_message(import, e, "Error parsing TTML file: no \"root\" found. Abort.");
		gf_xml_dom_del(parser);
		return e;
	}

	/*look for TTML*/
	if (gf_xml_get_element_check_namespace(root, "tt", NULL) == GF_OK) {
		e = gf_text_import_ebu_ttd(import, parser, root);
		if (e == GF_OK) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("Note: TTML import - EBU-TTD detected\n"));
		} else {
			GF_LOG(GF_LOG_INFO, GF_LOG_PARSER, ("Unsupported TTML file - only EBU-TTD is supported (root shall be \"tt\", got \"%s\")\n", root->name));
			GF_LOG(GF_LOG_INFO, GF_LOG_PARSER, ("Importing as generic TTML\n"));
			e = GF_OK;
		}
	} else {
		if (root->ns) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("TTML file not recognized: root element is \"%s:%s\" (check your namespaces)\n", root->ns, root->name));
		} else {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("TTML file not recognized: root element is \"%s\"\n", root->name));
		}
		e = GF_BAD_PARAM;
	}

	gf_xml_dom_del(parser);
	return e;
}

/* SimpleText Text tracks -related functions */
GF_Box *boxstring_new_with_data(u32 type, const char *string);

#ifndef GPAC_DISABLE_SWF_IMPORT

/* SWF Importer */
#include <gpac/internal/swf_dev.h>

static GF_Err swf_svg_add_iso_sample(void *user, const char *data, u32 length, u64 timestamp, Bool isRap)
{
	GF_Err				e = GF_OK;
	GF_ISOFlusher		*flusher = (GF_ISOFlusher *)user;
	GF_ISOSample		*s;
	GF_BitStream		*bs;

	bs = gf_bs_new(NULL, 0, GF_BITSTREAM_WRITE);
	if (!bs) return GF_BAD_PARAM;
	gf_bs_write_data(bs, data, length);
	s = gf_isom_sample_new();
	if (s) {
		gf_bs_get_content(bs, &s->data, &s->dataLength);
		s->DTS = (u64) (flusher->timescale*timestamp/1000);
		s->IsRAP = isRap ? RAP : RAP_NO;
		gf_isom_add_sample(flusher->import->dest, flusher->track, flusher->descriptionIndex, s);
		gf_isom_sample_del(&s);
	} else {
		e = GF_BAD_PARAM;
	}
	gf_bs_del(bs);
	return e;
}

static GF_Err swf_svg_add_iso_header(void *user, const char *data, u32 length, Bool isHeader)
{
	GF_ISOFlusher		*flusher = (GF_ISOFlusher *)user;
	if (!flusher) return GF_BAD_PARAM;
	if (isHeader) {
		return gf_isom_update_stxt_description(flusher->import->dest, flusher->track, NULL, data, flusher->descriptionIndex);
	} else {
		return gf_isom_append_sample_data(flusher->import->dest, flusher->track, (char *)data, length);
	}
}

GF_EXPORT
GF_Err gf_text_import_swf(GF_MediaImporter *import)
{
	GF_Err						e = GF_OK;
	u32							track;
	u32							timescale;
	//u32							duration;
	u32							descIndex;
	u32							ID;
	u32							OCR_ES_ID;
	GF_GenericSubtitleConfig	*cfg;
	SWFReader					*read;
	GF_ISOFlusher				flusher;
	char						*mime;

	if (import->flags & GF_IMPORT_PROBE_ONLY) {
		import->nb_tracks = 1;
		return GF_OK;
	}

	cfg	= NULL;
	if (import->esd) {
		if (!import->esd->slConfig)	{
			import->esd->slConfig =	(GF_SLConfig *)	gf_odf_desc_new(GF_ODF_SLC_TAG);
			import->esd->slConfig->predefined =	2;
			import->esd->slConfig->timestampResolution = 1000;
		}
		timescale =	import->esd->slConfig->timestampResolution;
		if (!timescale)	timescale =	1000;

		/*explicit text	config*/
		if (import->esd->decoderConfig && import->esd->decoderConfig->decoderSpecificInfo->tag == GF_ODF_GEN_SUB_CFG_TAG) {
			cfg	= (GF_GenericSubtitleConfig	*) import->esd->decoderConfig->decoderSpecificInfo;
			import->esd->decoderConfig->decoderSpecificInfo	= NULL;
		}
		ID = import->esd->ESID;
		OCR_ES_ID =	import->esd->OCRESID;
	} else {
		timescale =	1000;
		OCR_ES_ID =	ID = 0;
	}

	if (cfg	&& cfg->timescale) timescale = cfg->timescale;
	track =	gf_isom_new_track(import->dest,	ID,	GF_ISOM_MEDIA_TEXT,	timescale);
	if (!track)	{
		return gf_import_message(import, gf_isom_last_error(import->dest), "Error creating text track");
	}
	gf_isom_set_track_enabled(import->dest,	track, 1);
	if (import->esd	&& !import->esd->ESID) import->esd->ESID = gf_isom_get_track_id(import->dest, track);

	if (OCR_ES_ID) gf_isom_set_track_reference(import->dest, track,	GF_ISOM_REF_OCR, OCR_ES_ID);

	if (!stricmp(import->streamFormat, "SVG")) {
		mime = "image/svg+xml";
	} else {
		mime = "application/octet-stream";
	}
	/*setup	track*/
	if (cfg) {
		u32	i;
		u32	count;
		/*set track	info*/
		gf_isom_set_track_layout_info(import->dest,	track, cfg->text_width<<16,	cfg->text_height<<16, 0, 0,	cfg->layer);

		/*and set sample descriptions*/
		count =	gf_list_count(cfg->sample_descriptions);
		for	(i=0; i<count; i++)	{
			gf_isom_new_stxt_description(import->dest, track, GF_ISOM_SUBTYPE_STXT, mime, NULL, NULL, &descIndex);
		}
		gf_import_message(import, GF_OK, "SWF import - text track %d	x %d", cfg->text_width,	cfg->text_height);
		gf_odf_desc_del((GF_Descriptor *)cfg);
	} else {
		u32	w;
		u32	h;

		gf_text_get_video_size(import, &w, &h);
		gf_isom_set_track_layout_info(import->dest,	track, w<<16, h<<16, 0,	0, 0);

		gf_isom_new_stxt_description(import->dest, track, GF_ISOM_SUBTYPE_STXT, mime, NULL,	NULL, &descIndex);

		gf_import_message(import, GF_OK, "SWF import (as text - type: %s)", import->streamFormat);
	}
	gf_text_import_set_language(import, track);
	//duration = (u32) (((Double) import->duration)*timescale/1000.0);

	read = gf_swf_reader_new(NULL, import->in_name);
	gf_swf_read_header(read);
	flusher.import = import;
	flusher.track = track;
	flusher.timescale = timescale;
	flusher.descriptionIndex = descIndex;
	gf_swf_reader_set_user_mode(read, &flusher, swf_svg_add_iso_sample, swf_svg_add_iso_header);

	if (!import->streamFormat || (import->streamFormat && !stricmp(import->streamFormat, "SVG"))) {
#ifndef GPAC_DISABLE_SVG
		e = swf_to_svg_init(read, import->swf_flags, import->swf_flatten_angle);
#endif
	} else { /*if (import->streamFormat && !strcmp(import->streamFormat, "BIFS"))*/
#ifndef GPAC_DISABLE_VRML
		e = swf_to_bifs_init(read);
#endif
	}
	if (e) {
		goto exit;
	}
	/*parse all tags*/
	while (e == GF_OK) {
		e = swf_parse_tag(read);
	}
	if (e==GF_EOS) e = GF_OK;
exit:
	gf_swf_reader_del(read);
	return e;
}
/* end of SWF Importer */

#else

GF_EXPORT
GF_Err gf_text_import_swf(GF_MediaImporter *import)
{
	GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("Warning: GPAC was compiled without SWF import support, can't import track.\n"));
	return GF_NOT_SUPPORTED;
}

#endif /*GPAC_DISABLE_SWF_IMPORT*/

static GF_Err gf_text_process_sub(GF_Filter *filter, GF_TXTIn *ctx)
{
	u32 i, j, len, line;
	GF_Err e;
	GF_TextSample *samp;
	Double ts_scale;
	char szLine[2048], szTime[20], szText[2048];

	//same setup as for srt
	if (!ctx->is_setup) {
		ctx->is_setup = GF_TRUE;
		return txtin_setup_srt(filter, ctx);
	}
	if (!ctx->opid) return GF_NOT_SUPPORTED;


	e = GF_OK;
	if (ctx->fps.den && ctx->fps.num) {
		ts_scale = ((Double) ctx->timescale * ctx->fps.den) / ctx->fps.num;
	} else {
		ts_scale = ((Double) ctx->timescale ) / 25;
	}

	line = 0;

	while (1) {
		char *sOK = gf_text_get_utf8_line(szLine, 2048, ctx->src, ctx->unicode_type);
		if (!sOK) break;

		REM_TRAIL_MARKS(szLine, "\r\n\t ")

		line++;
		len = (u32) strlen(szLine);
		if (!len) continue;

		i=0;
		if (szLine[i] != '{') {
			GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Bad SUB file (line %d): expecting \"{\" got \"%c\"\n", line, szLine[i]));
			continue;
		}
		while (szLine[i+1] && szLine[i+1]!='}') {
			szTime[i] = szLine[i+1];
			i++;
		}
		szTime[i] = 0;
		ctx->start = atoi(szTime);
		if (ctx->start < ctx->end) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] corrupted SUB frame (line %d) - starts (at %d ms) before end of previous one (%d ms) - adjusting time stamps\n", line, ctx->start, ctx->end));
			ctx->start = ctx->end;
		}
		j=i+2;
		i=0;
		if (szLine[i+j] != '{') {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Bad SUB file - expecting \"{\" got \"%c\"\n", szLine[i]));
			continue;
		}
		while (szLine[i+1+j] && szLine[i+1+j]!='}') {
			szTime[i] = szLine[i+1+j];
			i++;
		}
		szTime[i] = 0;
		ctx->end = atoi(szTime);
		j+=i+2;

		if (ctx->start > ctx->end) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] corrupted SUB frame (line %d) - ends (at %d ms) before start of current frame (%d ms) - skipping\n", line, ctx->end, ctx->start));
			continue;
		}

		if (ctx->start && ctx->first_samp) {
			samp = gf_isom_new_text_sample();
			txtin_process_send_text_sample(ctx, samp, 0, (u64) (ts_scale*ctx->start), GF_TRUE);
			ctx->first_samp = GF_FALSE;
			gf_isom_delete_text_sample(samp);
		}

		for (i=j; i<len; i++) {
			if (szLine[i]=='|') {
				szText[i-j] = '\n';
			} else {
				szText[i-j] = szLine[i];
			}
		}
		szText[i-j] = 0;

		if (ctx->prev_end) {
			samp = gf_isom_new_text_sample();
			txtin_process_send_text_sample(ctx, samp, (ts_scale*(s64)ctx->prev_end), ts_scale*(ctx->prev_end - ctx->start), GF_TRUE);
			gf_isom_delete_text_sample(samp);
		}

		samp = gf_isom_new_text_sample();
		gf_isom_text_add_text(samp, szText, (u32) strlen(szText) );
		txtin_process_send_text_sample(ctx, samp, (ts_scale*(s64)ctx->start), ts_scale*(ctx->end - ctx->start), GF_TRUE);
		gf_isom_delete_text_sample(samp);

		ctx->prev_end = ctx->end;

		gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_BYTES, &PROP_UINT( gf_ftell(ctx->src )) );

		if (gf_filter_pid_would_block(ctx->opid))
			return GF_OK;
	}
	/*final flush*/
	if (ctx->end && !ctx->noflush) {
		samp = gf_isom_new_text_sample();
		txtin_process_send_text_sample(ctx, samp, (ts_scale*(s64)ctx->end), 0, GF_TRUE);
		gf_isom_delete_text_sample(samp);
	}

	gf_filter_pid_set_info_str( ctx->opid, "ttxt:last_dur", &PROP_UINT(0) );

	return GF_EOS;
}


#define CHECK_STR(__str)	\
	if (!__str) { \
		e = gf_import_message(import, GF_BAD_PARAM, "Invalid XML formatting (line %d)", parser.line);	\
		goto exit;	\
	}	\
 

u32 ttxt_get_color(char *val)
{
	u32 r, g, b, a, res;
	r = g = b = a = 0;
	if (sscanf(val, "%x %x %x %x", &r, &g, &b, &a) != 4) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_PARSER, ("[TXTIn] Warning: color badly formatted %s\n", val));
	}
	res = (a&0xFF);
	res<<=8;
	res |= (r&0xFF);
	res<<=8;
	res |= (g&0xFF);
	res<<=8;
	res |= (b&0xFF);
	return res;
}

void ttxt_parse_text_box(GF_XMLNode *n, GF_BoxRecord *box)
{
	u32 i=0;
	GF_XMLAttribute *att;
	memset(box, 0, sizeof(GF_BoxRecord));
	while ( (att=(GF_XMLAttribute *)gf_list_enum(n->attributes, &i))) {
		if (!stricmp(att->name, "top")) box->top = atoi(att->value);
		else if (!stricmp(att->name, "bottom")) box->bottom = atoi(att->value);
		else if (!stricmp(att->name, "left")) box->left = atoi(att->value);
		else if (!stricmp(att->name, "right")) box->right = atoi(att->value);
	}
}

void ttxt_parse_text_style(GF_XMLNode *n, GF_StyleRecord *style)
{
	u32 i=0;
	GF_XMLAttribute *att;
	memset(style, 0, sizeof(GF_StyleRecord));
	style->fontID = 1;
	style->font_size = TTXT_DEFAULT_FONT_SIZE;
	style->text_color = 0xFFFFFFFF;

	while ( (att=(GF_XMLAttribute *)gf_list_enum(n->attributes, &i))) {
		if (!stricmp(att->name, "fromChar")) style->startCharOffset = atoi(att->value);
		else if (!stricmp(att->name, "toChar")) style->endCharOffset = atoi(att->value);
		else if (!stricmp(att->name, "fontID")) style->fontID = atoi(att->value);
		else if (!stricmp(att->name, "fontSize")) style->font_size = atoi(att->value);
		else if (!stricmp(att->name, "color")) style->text_color = ttxt_get_color(att->value);
		else if (!stricmp(att->name, "styles")) {
			if (strstr(att->value, "Bold")) style->style_flags |= GF_TXT_STYLE_BOLD;
			if (strstr(att->value, "Italic")) style->style_flags |= GF_TXT_STYLE_ITALIC;
			if (strstr(att->value, "Underlined")) style->style_flags |= GF_TXT_STYLE_UNDERLINED;
		}
	}
}

static void ttxt_dom_progress(void *cbk, u64 cur_samp, u64 count)
{
	GF_TXTIn *ctx = (GF_TXTIn *)cbk;
	ctx->end = count;
}

static GF_Err txtin_setup_ttxt(GF_Filter *filter, GF_TXTIn *ctx)
{
	GF_Err e;
	u32 j, k, ID, OCR_ES_ID;
	u64 file_size;
	GF_XMLAttribute *att;
	GF_XMLNode *root, *node, *ext;
	GF_PropertyValue *dcd;

	ctx->parser = gf_xml_dom_new();
	e = gf_xml_dom_parse(ctx->parser, ctx->file_name, ttxt_dom_progress, ctx);
	if (e) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Error parsing TTXT file: Line %d - %s\n", gf_xml_dom_get_line(ctx->parser), gf_xml_dom_get_error(ctx->parser)));
		return e;
	}
	root = gf_xml_dom_get_root(ctx->parser);

	e = GF_OK;
	if (strcmp(root->name, "TextStream")) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Invalid Timed Text file - expecting \"TextStream\" got %s", root->name));
		return GF_NON_COMPLIANT_BITSTREAM;
	}
	file_size = ctx->end;
	ctx->end = 0;

	/*setup track in 3GP format directly (no ES desc)*/
	if (!ctx->timescale) ctx->timescale = 1000;
	OCR_ES_ID = ID = 0;

	if (!ctx->opid) ctx->opid = gf_filter_pid_new(filter);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_TEXT) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_OTI, &PROP_UINT(GF_ISOM_SUBTYPE_TX3G) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_TIMESCALE, &PROP_UINT(ctx->timescale) );
	gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_SIZE, &PROP_UINT(file_size) );

	if (!ID) ID = 1;
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ID, &PROP_UINT(ID) );
	if (OCR_ES_ID) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CLOCK_ID, &PROP_UINT(OCR_ES_ID) );

	ctx->nb_children = gf_list_count(root->content);

	ctx->cur_child_idx = 0;
	for (ctx->cur_child_idx=0; ctx->cur_child_idx < ctx->nb_children; ctx->cur_child_idx++) {
		node = (GF_XMLNode*) gf_list_get(root->content, ctx->cur_child_idx);

		if (node->type) {
			continue;
		}

		if (!strcmp(node->name, "TextStreamHeader")) {
			GF_XMLNode *sdesc;
			s32 w, h, tx, ty, layer;
			u32 tref_id;
			w = ctx->width;
			h = ctx->height;
			tx = ctx->x;
			ty = ctx->y;
			layer = ctx->zorder;
			tref_id = 0;

			j=0;
			while ( (att=(GF_XMLAttribute *)gf_list_enum(node->attributes, &j))) {
				if (!strcmp(att->name, "width")) w = atoi(att->value);
				else if (!strcmp(att->name, "height")) h = atoi(att->value);
				else if (!strcmp(att->name, "layer")) layer = atoi(att->value);
				else if (!strcmp(att->name, "translation_x")) tx = atoi(att->value);
				else if (!strcmp(att->name, "translation_y")) ty = atoi(att->value);
				else if (!strcmp(att->name, "trefID")) tref_id = atoi(att->value);
			}

			if (tref_id) {
				gf_filter_pid_set_property_str(ctx->opid, "tref:chap", &PROP_UINT(tref_id) );
			}

			if (w) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx->width) );
			if (h) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx->height) );
			if (layer) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ZORDER, &PROP_SINT(ctx->zorder) );
			if (ctx->lang) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_LANGUAGE, &PROP_STRING((char *) ctx->lang) );

			j=0;
			while ( (sdesc=(GF_XMLNode*)gf_list_enum(node->content, &j))) {
				if (sdesc->type) continue;

				if (!strcmp(sdesc->name, "TextSampleDescription")) {
					GF_TextSampleDescriptor td;
					memset(&td, 0, sizeof(GF_TextSampleDescriptor));
					td.tag = GF_ODF_TEXT_CFG_TAG;
					td.vert_justif = (s8) -1;
					td.default_style.fontID = 1;
					td.default_style.font_size = TTXT_DEFAULT_FONT_SIZE;

					k=0;
					while ( (att=(GF_XMLAttribute *)gf_list_enum(sdesc->attributes, &k))) {
						if (!strcmp(att->name, "horizontalJustification")) {
							if (!stricmp(att->value, "center")) td.horiz_justif = 1;
							else if (!stricmp(att->value, "right")) td.horiz_justif = (s8) -1;
							else if (!stricmp(att->value, "left")) td.horiz_justif = 0;
						}
						else if (!strcmp(att->name, "verticalJustification")) {
							if (!stricmp(att->value, "center")) td.vert_justif = 1;
							else if (!stricmp(att->value, "bottom")) td.vert_justif = (s8) -1;
							else if (!stricmp(att->value, "top")) td.vert_justif = 0;
						}
						else if (!strcmp(att->name, "backColor")) td.back_color = ttxt_get_color(att->value);
						else if (!strcmp(att->name, "verticalText") && !stricmp(att->value, "yes") ) td.displayFlags |= GF_TXT_VERTICAL;
						else if (!strcmp(att->name, "fillTextRegion") && !stricmp(att->value, "yes") ) td.displayFlags |= GF_TXT_FILL_REGION;
						else if (!strcmp(att->name, "continuousKaraoke") && !stricmp(att->value, "yes") ) td.displayFlags |= GF_TXT_KARAOKE;
						else if (!strcmp(att->name, "scroll")) {
							if (!stricmp(att->value, "inout")) td.displayFlags |= GF_TXT_SCROLL_IN | GF_TXT_SCROLL_OUT;
							else if (!stricmp(att->value, "in")) td.displayFlags |= GF_TXT_SCROLL_IN;
							else if (!stricmp(att->value, "out")) td.displayFlags |= GF_TXT_SCROLL_OUT;
						}
						else if (!strcmp(att->name, "scrollMode")) {
							u32 scroll_mode = GF_TXT_SCROLL_CREDITS;
							if (!stricmp(att->value, "Credits")) scroll_mode = GF_TXT_SCROLL_CREDITS;
							else if (!stricmp(att->value, "Marquee")) scroll_mode = GF_TXT_SCROLL_MARQUEE;
							else if (!stricmp(att->value, "Right")) scroll_mode = GF_TXT_SCROLL_RIGHT;
							else if (!stricmp(att->value, "Down")) scroll_mode = GF_TXT_SCROLL_DOWN;
							td.displayFlags |= ((scroll_mode<<7) & GF_TXT_SCROLL_DIRECTION);
						}
					}

					k=0;
					while ( (ext=(GF_XMLNode*)gf_list_enum(sdesc->content, &k))) {
						if (ext->type) continue;
						if (!strcmp(ext->name, "TextBox")) ttxt_parse_text_box(ext, &td.default_pos);
						else if (!strcmp(ext->name, "Style")) ttxt_parse_text_style(ext, &td.default_style);
						else if (!strcmp(ext->name, "FontTable")) {
							GF_XMLNode *ftable;
							u32 z=0;
							while ( (ftable=(GF_XMLNode*)gf_list_enum(ext->content, &z))) {
								u32 m;
								if (ftable->type || strcmp(ftable->name, "FontTableEntry")) continue;
								td.font_count += 1;
								td.fonts = (GF_FontRecord*)gf_realloc(td.fonts, sizeof(GF_FontRecord)*td.font_count);
								m=0;
								while ( (att=(GF_XMLAttribute *)gf_list_enum(ftable->attributes, &m))) {
									if (!stricmp(att->name, "fontID")) td.fonts[td.font_count-1].fontID = atoi(att->value);
									else if (!stricmp(att->name, "fontName")) td.fonts[td.font_count-1].fontName = gf_strdup(att->value);
								}
							}
						}
					}
					if (ctx->nodefbox) {
						td.default_pos.top = td.default_pos.left = td.default_pos.right = td.default_pos.bottom = 0;
					} else {
						if ((td.default_pos.bottom==td.default_pos.top) || (td.default_pos.right==td.default_pos.left)) {
							td.default_pos.top = td.default_pos.left = 0;
							td.default_pos.right = w;
							td.default_pos.bottom = h;
						}
					}
					if (!td.fonts) {
						td.font_count = 1;
						td.fonts = (GF_FontRecord*)gf_malloc(sizeof(GF_FontRecord));
						td.fonts[0].fontID = 1;
						td.fonts[0].fontName = gf_strdup("Serif");
					}
					GF_SAFEALLOC(dcd, GF_PropertyValue);
					dcd->type = GF_PROP_DATA;

					gf_odf_tx3g_write(&td, &dcd->value.data.ptr, &dcd->value.data.size);
					if (!ctx->text_descs) ctx->text_descs = gf_list_new();
					gf_list_add(ctx->text_descs, dcd);

					for (k=0; k<td.font_count; k++) gf_free(td.fonts[k].fontName);
					gf_free(td.fonts);
				}
			}
		}
		else {
			break;
		}
	}

	if (!ctx->text_descs) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Invalid Timed Text file - text stream header not found or empty\n"));
		return GF_NON_COMPLIANT_BITSTREAM;
	}
	dcd = gf_list_get(ctx->text_descs, 0);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, dcd);
	ctx->last_desc_idx = 1;

	ctx->first_samp = GF_TRUE;
	ctx->last_sample_empty = GF_FALSE;

#ifdef FILTER_FIXME
	last_sample_duration = 0;
	nb_descs = 0;
	nb_samples = 0;
#endif

	return GF_OK;
}

static GF_Err txtin_process_ttxt(GF_Filter *filter, GF_TXTIn *ctx)
{
	u32 j, k;
	GF_XMLAttribute *att;
	GF_XMLNode *root, *node, *ext;

	if (!ctx->is_setup) {
		ctx->is_setup = GF_TRUE;
		return txtin_setup_ttxt(filter, ctx);
	}
	if (!ctx->opid) return GF_NON_COMPLIANT_BITSTREAM;

	root = gf_xml_dom_get_root(ctx->parser);

	for (; ctx->cur_child_idx < ctx->nb_children; ctx->cur_child_idx++) {
		GF_TextSample * samp;
		u32 ts, descIndex;
		Bool has_text = GF_FALSE;

		if (gf_filter_pid_would_block(ctx->opid))
			return GF_OK;

		node = (GF_XMLNode*) gf_list_get(root->content, ctx->cur_child_idx);

		if (node->type) {
			continue;
		}
		/*sample text*/
		else if (strcmp(node->name, "TextSample")) continue;

		samp = gf_isom_new_text_sample();
		ts = 0;
		descIndex = 1;
		ctx->last_sample_empty = GF_TRUE;

		j=0;
		while ( (att=(GF_XMLAttribute*)gf_list_enum(node->attributes, &j))) {
			if (!strcmp(att->name, "sampleTime")) {
				u32 h, m, s, ms;
				if (sscanf(att->value, "%u:%u:%u.%u", &h, &m, &s, &ms) == 4) {
					ts = (h*3600 + m*60 + s)*1000 + ms;
				} else {
					ts = (u32) (atof(att->value) * 1000);
				}
			}
			else if (!strcmp(att->name, "sampleDescriptionIndex")) descIndex = atoi(att->value);
			else if (!strcmp(att->name, "text")) {
				u32 len;
				char *str = ttxt_parse_string(att->value, GF_TRUE);
				len = (u32) strlen(str);
				gf_isom_text_add_text(samp, str, len);
				ctx->last_sample_empty = len ? GF_FALSE : GF_TRUE;
				has_text = GF_TRUE;
			}
			else if (!strcmp(att->name, "scrollDelay")) gf_isom_text_set_scroll_delay(samp, (u32) (1000*atoi(att->value)));
			else if (!strcmp(att->name, "highlightColor")) gf_isom_text_set_highlight_color_argb(samp, ttxt_get_color(att->value));
			else if (!strcmp(att->name, "wrap") && !strcmp(att->value, "Automatic")) gf_isom_text_set_wrap(samp, 0x01);
		}

		/*get all modifiers*/
		j=0;
		while ( (ext=(GF_XMLNode*)gf_list_enum(node->content, &j))) {
			if (!has_text && (ext->type==GF_XML_TEXT_TYPE)) {
				u32 len;
				char *str = ttxt_parse_string(ext->name, GF_FALSE);
				len = (u32) strlen(str);
				gf_isom_text_add_text(samp, str, len);
				ctx->last_sample_empty = len ? GF_FALSE : GF_TRUE;
				has_text = GF_TRUE;
			}
			if (ext->type) continue;

			if (!stricmp(ext->name, "Style")) {
				GF_StyleRecord r;
				ttxt_parse_text_style(ext, &r);
				gf_isom_text_add_style(samp, &r);
			}
			else if (!stricmp(ext->name, "TextBox")) {
				GF_BoxRecord r;
				ttxt_parse_text_box(ext, &r);
				gf_isom_text_set_box(samp, r.top, r.left, r.bottom, r.right);
			}
			else if (!stricmp(ext->name, "Highlight")) {
				u16 start, end;
				start = end = 0;
				k=0;
				while ( (att=(GF_XMLAttribute *)gf_list_enum(ext->attributes, &k))) {
					if (!strcmp(att->name, "fromChar")) start = atoi(att->value);
					else if (!strcmp(att->name, "toChar")) end = atoi(att->value);
				}
				gf_isom_text_add_highlight(samp, start, end);
			}
			else if (!stricmp(ext->name, "Blinking")) {
				u16 start, end;
				start = end = 0;
				k=0;
				while ( (att=(GF_XMLAttribute *)gf_list_enum(ext->attributes, &k))) {
					if (!strcmp(att->name, "fromChar")) start = atoi(att->value);
					else if (!strcmp(att->name, "toChar")) end = atoi(att->value);
				}
				gf_isom_text_add_blink(samp, start, end);
			}
			else if (!stricmp(ext->name, "HyperLink")) {
				u16 start, end;
				char *url, *url_tt;
				start = end = 0;
				url = url_tt = NULL;
				k=0;
				while ( (att=(GF_XMLAttribute *)gf_list_enum(ext->attributes, &k))) {
					if (!strcmp(att->name, "fromChar")) start = atoi(att->value);
					else if (!strcmp(att->name, "toChar")) end = atoi(att->value);
					else if (!strcmp(att->name, "URL")) url = gf_strdup(att->value);
					else if (!strcmp(att->name, "URLToolTip")) url_tt = gf_strdup(att->value);
				}
				gf_isom_text_add_hyperlink(samp, url, url_tt, start, end);
				if (url) gf_free(url);
				if (url_tt) gf_free(url_tt);
			}
			else if (!stricmp(ext->name, "Karaoke")) {
				u32 startTime;
				GF_XMLNode *krok;
				startTime = 0;
				k=0;
				while ( (att=(GF_XMLAttribute *)gf_list_enum(ext->attributes, &k))) {
					if (!strcmp(att->name, "startTime")) startTime = (u32) (1000*atof(att->value));
				}
				gf_isom_text_add_karaoke(samp, startTime);
				k=0;
				while ( (krok=(GF_XMLNode*)gf_list_enum(ext->content, &k))) {
					u16 start, end;
					u32 endTime, m;
					if (krok->type) continue;
					if (strcmp(krok->name, "KaraokeRange")) continue;
					start = end = 0;
					endTime = 0;
					m=0;
					while ( (att=(GF_XMLAttribute *)gf_list_enum(krok->attributes, &m))) {
						if (!strcmp(att->name, "fromChar")) start = atoi(att->value);
						else if (!strcmp(att->name, "toChar")) end = atoi(att->value);
						else if (!strcmp(att->name, "endTime")) endTime = (u32) (1000*atof(att->value));
					}
					gf_isom_text_set_karaoke_segment(samp, endTime, start, end);
				}
			}
		}

		if (!descIndex) descIndex = 1;
		if (descIndex != ctx->last_desc_idx) {
			GF_PropertyValue *dcd;
			ctx->last_desc_idx = descIndex;
			dcd = gf_list_get(ctx->text_descs, descIndex-1);
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, dcd);
		}

		/*in MP4 we must start at T=0, so add an empty sample*/
		if (ts && ctx->first_samp) {
			GF_TextSample * firstsamp = gf_isom_new_text_sample();
			txtin_process_send_text_sample(ctx, firstsamp, 0, 0, GF_TRUE);
			gf_isom_delete_text_sample(firstsamp);
		}
		ctx->first_samp = GF_FALSE;

		txtin_process_send_text_sample(ctx, samp, ts, 0, GF_TRUE);

		gf_isom_delete_text_sample(samp);

		if (ctx->last_sample_empty) {
			ctx->last_sample_duration = ts - ctx->last_sample_duration;
		} else {
			ctx->last_sample_duration = ts;
		}
	}

	if (ctx->last_sample_empty) {
		//this is a bit ugly, in regular streaming mode we don't want to remove empty samples
		//howvere the last one can be removed, adjusting the duration of the previous one.
		//doing this here is problematic if the loader is sent a new ttxt file, we would have a cue termination sample
		//we therefore share that info through pid, and let the final user (muxer& co) decide what to do
		gf_filter_pid_set_info_str( ctx->opid, "ttxt:rem_last", &PROP_BOOL(GF_TRUE) );
		gf_filter_pid_set_info_str( ctx->opid, "ttxt:last_dur", &PROP_UINT(ctx->last_sample_duration) );
	}

	return GF_EOS;
}


u32 tx3g_get_color(char *value)
{
	u32 r, g, b, a;
	u32 res, v;
	r = g = b = a = 0;
	if (sscanf(value, "%u%%, %u%%, %u%%, %u%%", &r, &g, &b, &a) != 4) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("Warning: color badly formatted\n"));
	}
	v = (u32) (a*255/100);
	res = (v&0xFF);
	res<<=8;
	v = (u32) (r*255/100);
	res |= (v&0xFF);
	res<<=8;
	v = (u32) (g*255/100);
	res |= (v&0xFF);
	res<<=8;
	v = (u32) (b*255/100);
	res |= (v&0xFF);
	return res;
}

void tx3g_parse_text_box(GF_XMLNode *n, GF_BoxRecord *box)
{
	u32 i=0;
	GF_XMLAttribute *att;
	memset(box, 0, sizeof(GF_BoxRecord));
	while ((att=(GF_XMLAttribute *)gf_list_enum(n->attributes, &i))) {
		if (!stricmp(att->name, "x")) box->left = atoi(att->value);
		else if (!stricmp(att->name, "y")) box->top = atoi(att->value);
		else if (!stricmp(att->name, "height")) box->bottom = atoi(att->value);
		else if (!stricmp(att->name, "width")) box->right = atoi(att->value);
	}
}

typedef struct
{
	u32 id;
	u32 pos;
} Marker;

#define GET_MARKER_POS(_val, __isend) \
	{	\
		u32 i, __m = atoi(att->value);	\
		_val = 0;	\
		for (i=0; i<nb_marks; i++) { if (__m==marks[i].id) { _val = marks[i].pos; /*if (__isend) _val--; */break; } }	 \
	}


static GF_Err txtin_texml_setup(GF_Filter *filter, GF_TXTIn *ctx)
{
	GF_Err e;
	u32 ID, OCR_ES_ID, i;
	u64 file_size;
	GF_XMLAttribute *att;
	GF_XMLNode *root;

	ctx->parser = gf_xml_dom_new();
	e = gf_xml_dom_parse(ctx->parser, ctx->file_name, ttxt_dom_progress, ctx);
	if (e) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Error parsing TeXML file: Line %d - %s", gf_xml_dom_get_line(ctx->parser), gf_xml_dom_get_error(ctx->parser) ));
		gf_xml_dom_del(ctx->parser);
		ctx->parser = NULL;
		return e;
	}

	root = gf_xml_dom_get_root(ctx->parser);

	if (strcmp(root->name, "text3GTrack")) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTIn] Invalid QT TeXML file - expecting root \"text3GTrack\" got \"%s\"", root->name));
		return GF_NON_COMPLIANT_BITSTREAM;
	}
	file_size = ctx->end;

	i=0;
	while ( (att=(GF_XMLAttribute *)gf_list_enum(root->attributes, &i))) {
		if (!strcmp(att->name, "trackWidth")) ctx->width = atoi(att->value);
		else if (!strcmp(att->name, "trackHeight")) ctx->height = atoi(att->value);
		else if (!strcmp(att->name, "layer")) ctx->zorder = atoi(att->value);
		else if (!strcmp(att->name, "timeScale")) ctx->timescale = atoi(att->value);
		else if (!strcmp(att->name, "transform")) {
			Float fx, fy;
			sscanf(att->value, "translate(%f,%f)", &fx, &fy);
			ctx->x = (u32) fx;
			ctx->y = (u32) fy;
		}
	}

	/*setup track in 3GP format directly (no ES desc)*/
	OCR_ES_ID = ID = 0;
	if (!ctx->timescale) ctx->timescale = 1000;

	if (!ctx->opid) ctx->opid = gf_filter_pid_new(filter);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_TEXT) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_OTI, &PROP_UINT(GF_ISOM_SUBTYPE_TX3G) );
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_TIMESCALE, &PROP_UINT(ctx->timescale) );
	gf_filter_pid_set_info(ctx->opid, GF_PROP_PID_DOWN_SIZE, &PROP_UINT(file_size) );


	if (!ID) ID = 1;
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ID, &PROP_UINT(ID) );
	if (OCR_ES_ID) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CLOCK_ID, &PROP_UINT(OCR_ES_ID) );
	if (ctx->width) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx->width) );
	if (ctx->height) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx->height) );
	if (ctx->zorder) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_ZORDER, &PROP_SINT(ctx->zorder) );
	if (ctx->lang) gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_LANGUAGE, &PROP_STRING((char *) ctx->lang) );


	ctx->nb_children = gf_list_count(root->content);
	ctx->cur_child_idx = 0;

	return GF_OK;
}

static GF_Err txtin_process_texml(GF_Filter *filter, GF_TXTIn *ctx)
{
	u32 j, k;
	GF_StyleRecord styles[50];
	Marker marks[50];
	GF_XMLAttribute *att;
	GF_XMLNode *root;
	Bool probe_first_desc_only = GF_FALSE;

	if (!ctx->is_setup) {
		GF_Err e;

		ctx->is_setup = GF_TRUE;
		e = txtin_texml_setup(filter, ctx);
		if (e) return e;
		probe_first_desc_only = GF_TRUE;
	}
	if (!ctx->opid) return GF_NON_COMPLIANT_BITSTREAM;

	root = gf_xml_dom_get_root(ctx->parser);

	for (; ctx->cur_child_idx < ctx->nb_children; ctx->cur_child_idx++) {
		GF_XMLNode *node, *desc;
		GF_TextSampleDescriptor td;
		GF_TextSample * samp = NULL;
		u32 duration, descIndex, nb_styles, nb_marks;
		Bool isRAP, same_style, same_box;

		if (probe_first_desc_only && ctx->text_descs && gf_list_count(ctx->text_descs))
			return GF_OK;

		if (gf_filter_pid_would_block(ctx->opid))
			return GF_OK;


		node = (GF_XMLNode*)gf_list_get(root->content, ctx->cur_child_idx);
		if (node->type) continue;
		if (strcmp(node->name, "sample")) continue;

		isRAP = GF_TRUE;
		duration = 1000;
		j=0;
		while ((att=(GF_XMLAttribute *)gf_list_enum(node->attributes, &j))) {
			if (!strcmp(att->name, "duration")) duration = atoi(att->value);
			else if (!strcmp(att->name, "keyframe")) isRAP = (!stricmp(att->value, "true") ? GF_TRUE : GF_FALSE);
		}
		nb_styles = 0;
		nb_marks = 0;
		same_style = same_box = GF_FALSE;
		descIndex = 1;
		j=0;
		while ((desc=(GF_XMLNode*)gf_list_enum(node->content, &j))) {
			if (desc->type) continue;

			if (!strcmp(desc->name, "description")) {
				char *dsi;
				u32 dsi_len, k, stsd_idx;
				GF_XMLNode *sub;
				memset(&td, 0, sizeof(GF_TextSampleDescriptor));
				td.tag = GF_ODF_TEXT_CFG_TAG;
				td.vert_justif = (s8) -1;
				td.default_style.fontID = 1;
				td.default_style.font_size = ctx->fontsize;

				k=0;
				while ((att=(GF_XMLAttribute *)gf_list_enum(desc->attributes, &k))) {
					if (!strcmp(att->name, "horizontalJustification")) {
						if (!stricmp(att->value, "center")) td.horiz_justif = 1;
						else if (!stricmp(att->value, "right")) td.horiz_justif = (s8) -1;
						else if (!stricmp(att->value, "left")) td.horiz_justif = 0;
					}
					else if (!strcmp(att->name, "verticalJustification")) {
						if (!stricmp(att->value, "center")) td.vert_justif = 1;
						else if (!stricmp(att->value, "bottom")) td.vert_justif = (s8) -1;
						else if (!stricmp(att->value, "top")) td.vert_justif = 0;
					}
					else if (!strcmp(att->name, "backgroundColor")) td.back_color = tx3g_get_color(att->value);
					else if (!strcmp(att->name, "displayFlags")) {
						Bool rev_scroll = GF_FALSE;
						if (strstr(att->value, "scroll")) {
							u32 scroll_mode = 0;
							if (strstr(att->value, "scrollIn")) td.displayFlags |= GF_TXT_SCROLL_IN;
							if (strstr(att->value, "scrollOut")) td.displayFlags |= GF_TXT_SCROLL_OUT;
							if (strstr(att->value, "reverse")) rev_scroll = GF_TRUE;
							if (strstr(att->value, "horizontal")) scroll_mode = rev_scroll ? GF_TXT_SCROLL_RIGHT : GF_TXT_SCROLL_MARQUEE;
							else scroll_mode = (rev_scroll ? GF_TXT_SCROLL_DOWN : GF_TXT_SCROLL_CREDITS);
							td.displayFlags |= (scroll_mode<<7) & GF_TXT_SCROLL_DIRECTION;
						}
						/*TODO FIXME: check in QT doc !!*/
						if (strstr(att->value, "writeTextVertically")) td.displayFlags |= GF_TXT_VERTICAL;
						if (!strcmp(att->name, "continuousKaraoke")) td.displayFlags |= GF_TXT_KARAOKE;
					}
				}

				k=0;
				while ((sub=(GF_XMLNode*)gf_list_enum(desc->content, &k))) {
					if (sub->type) continue;
					if (!strcmp(sub->name, "defaultTextBox")) tx3g_parse_text_box(sub, &td.default_pos);
					else if (!strcmp(sub->name, "fontTable")) {
						GF_XMLNode *ftable;
						u32 m=0;
						while ((ftable=(GF_XMLNode*)gf_list_enum(sub->content, &m))) {
							if (ftable->type) continue;
							if (!strcmp(ftable->name, "font")) {
								u32 n=0;
								td.font_count += 1;
								td.fonts = (GF_FontRecord*)gf_realloc(td.fonts, sizeof(GF_FontRecord)*td.font_count);
								while ((att=(GF_XMLAttribute *)gf_list_enum(ftable->attributes, &n))) {
									if (!stricmp(att->name, "id")) td.fonts[td.font_count-1].fontID = atoi(att->value);
									else if (!stricmp(att->name, "name")) td.fonts[td.font_count-1].fontName = gf_strdup(att->value);
								}
							}
						}
					}
					else if (!strcmp(sub->name, "sharedStyles")) {
						GF_XMLNode *style, *ftable;
						u32 m=0;
						while ((style=(GF_XMLNode*)gf_list_enum(sub->content, &m))) {
							if (style->type) continue;
							if (!strcmp(style->name, "style")) break;
						}
						if (style) {
							char *cur;
							s32 start=0;
							char css_style[1024], css_val[1024];
							memset(&styles[nb_styles], 0, sizeof(GF_StyleRecord));
							m=0;
							while ( (att=(GF_XMLAttribute *)gf_list_enum(style->attributes, &m))) {
								if (!strcmp(att->name, "id")) styles[nb_styles].startCharOffset = atoi(att->value);
							}
							m=0;
							while ( (ftable=(GF_XMLNode*)gf_list_enum(style->content, &m))) {
								if (ftable->type) break;
							}
							cur = ftable->name;
							while (cur) {
								start = gf_token_get_strip(cur, 0, "{:", " ", css_style, 1024);
								if (start <0) break;
								start = gf_token_get_strip(cur, start, ":}", " ", css_val, 1024);
								if (start <0) break;
								cur = strchr(cur+start, '{');

								if (!strcmp(css_style, "font-table")) {
									u32 z;
									styles[nb_styles].fontID = atoi(css_val);
									for (z=0; z<td.font_count; z++) {
										if (td.fonts[z].fontID == styles[nb_styles].fontID)
											break;
									}
								}
								else if (!strcmp(css_style, "font-size")) styles[nb_styles].font_size = atoi(css_val);
								else if (!strcmp(css_style, "font-style") && !strcmp(css_val, "italic")) styles[nb_styles].style_flags |= GF_TXT_STYLE_ITALIC;
								else if (!strcmp(css_style, "font-weight") && !strcmp(css_val, "bold")) styles[nb_styles].style_flags |= GF_TXT_STYLE_BOLD;
								else if (!strcmp(css_style, "text-decoration") && !strcmp(css_val, "underline")) styles[nb_styles].style_flags |= GF_TXT_STYLE_UNDERLINED;
								else if (!strcmp(css_style, "color")) styles[nb_styles].text_color = tx3g_get_color(css_val);
							}
							if (!nb_styles) td.default_style = styles[0];
							nb_styles++;
						}
					}

				}
				if ((td.default_pos.bottom==td.default_pos.top) || (td.default_pos.right==td.default_pos.left)) {
					td.default_pos.top = ctx->y;
					td.default_pos.left = ctx->x;
					td.default_pos.right = ctx->width;
					td.default_pos.bottom = ctx->height;
				}
				if (!td.fonts) {
					td.font_count = 1;
					td.fonts = (GF_FontRecord*)gf_malloc(sizeof(GF_FontRecord));
					td.fonts[0].fontID = 1;
					td.fonts[0].fontName = gf_strdup( ctx->fontname ? ctx->fontname : "Serif");
				}

				gf_odf_tx3g_write(&td, &dsi, &dsi_len);
				stsd_idx = 0;
				for (k=0; ctx->text_descs && k<gf_list_count(ctx->text_descs); k++) {
					GF_PropertyValue *d = gf_list_get(ctx->text_descs, k);
					if (d->value.data.size != dsi_len) continue;
					if (! memcmp(d->value.data.ptr, dsi, dsi_len)) {
						stsd_idx = k+1;
						break;
					}
				}
				if (stsd_idx) {
					gf_free(dsi);
				} else {
					GF_PropertyValue *d;
					GF_SAFEALLOC(d, GF_PropertyValue);
					d->type = GF_PROP_DATA;
					d->value.data.ptr = dsi;
					d->value.data.size = dsi_len;
					if (!ctx->text_descs) ctx->text_descs = gf_list_new();
					gf_list_add(ctx->text_descs, d);
					stsd_idx = gf_list_count(ctx->text_descs);
				}
				if (stsd_idx != ctx->last_desc_idx) {
					ctx->last_desc_idx = stsd_idx;
					GF_PropertyValue *d = gf_list_get(ctx->text_descs, stsd_idx-1);
					gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, d);
				}

				for (k=0; k<td.font_count; k++) gf_free(td.fonts[k].fontName);
				gf_free(td.fonts);
			}
			else if (!strcmp(desc->name, "sampleData")) {
				GF_XMLNode *sub;
				u16 start, end;
				u32 styleID;
				u32 nb_chars, txt_len, m;
				nb_chars = 0;

				samp = gf_isom_new_text_sample();

				k=0;
				while ((att=(GF_XMLAttribute *)gf_list_enum(desc->attributes, &k))) {
					if (!strcmp(att->name, "targetEncoding") && !strcmp(att->value, "utf16")) ;//is_utf16 = 1;
					else if (!strcmp(att->name, "scrollDelay")) gf_isom_text_set_scroll_delay(samp, atoi(att->value) );
					else if (!strcmp(att->name, "highlightColor")) gf_isom_text_set_highlight_color_argb(samp, tx3g_get_color(att->value));
				}
				start = end = 0;
				k=0;
				while ((sub=(GF_XMLNode*)gf_list_enum(desc->content, &k))) {
					if (sub->type) continue;
					if (!strcmp(sub->name, "text")) {
						GF_XMLNode *text;
						styleID = 0;
						m=0;
						while ((att=(GF_XMLAttribute *)gf_list_enum(sub->attributes, &m))) {
							if (!strcmp(att->name, "styleID")) styleID = atoi(att->value);
						}
						txt_len = 0;

						m=0;
						while ((text=(GF_XMLNode*)gf_list_enum(sub->content, &m))) {
							if (!text->type) {
								if (!strcmp(text->name, "marker")) {
									u32 z;
									memset(&marks[nb_marks], 0, sizeof(Marker));
									marks[nb_marks].pos = nb_chars+txt_len;

									z = 0;
									while ( (att=(GF_XMLAttribute *)gf_list_enum(text->attributes, &z))) {
										if (!strcmp(att->name, "id")) marks[nb_marks].id = atoi(att->value);
									}
									nb_marks++;
								}
							} else if (text->type==GF_XML_TEXT_TYPE) {
								txt_len += (u32) strlen(text->name);
								gf_isom_text_add_text(samp, text->name, (u32) strlen(text->name));
							}
						}
						if (styleID && (!same_style || (td.default_style.startCharOffset != styleID))) {
							GF_StyleRecord st = td.default_style;
							for (m=0; m<nb_styles; m++) {
								if (styles[m].startCharOffset==styleID) {
									st = styles[m];
									break;
								}
							}
							st.startCharOffset = nb_chars;
							st.endCharOffset = nb_chars + txt_len;
							gf_isom_text_add_style(samp, &st);
						}
						nb_chars += txt_len;
					}
					else if (!stricmp(sub->name, "highlight")) {
						m=0;
						while ((att=(GF_XMLAttribute *)gf_list_enum(sub->attributes, &m))) {
							if (!strcmp(att->name, "startMarker")) GET_MARKER_POS(start, 0)
								else if (!strcmp(att->name, "endMarker")) GET_MARKER_POS(end, 1)
								}
						gf_isom_text_add_highlight(samp, start, end);
					}
					else if (!stricmp(sub->name, "blink")) {
						m=0;
						while ((att=(GF_XMLAttribute *)gf_list_enum(sub->attributes, &m))) {
							if (!strcmp(att->name, "startMarker")) GET_MARKER_POS(start, 0)
								else if (!strcmp(att->name, "endMarker")) GET_MARKER_POS(end, 1)
								}
						gf_isom_text_add_blink(samp, start, end);
					}
					else if (!stricmp(sub->name, "link")) {
						char *url, *url_tt;
						url = url_tt = NULL;
						m=0;
						while ((att=(GF_XMLAttribute *)gf_list_enum(sub->attributes, &m))) {
							if (!strcmp(att->name, "startMarker")) GET_MARKER_POS(start, 0)
								else if (!strcmp(att->name, "endMarker")) GET_MARKER_POS(end, 1)
									else if (!strcmp(att->name, "URL") || !strcmp(att->name, "href")) url = gf_strdup(att->value);
									else if (!strcmp(att->name, "URLToolTip") || !strcmp(att->name, "altString")) url_tt = gf_strdup(att->value);
						}
						gf_isom_text_add_hyperlink(samp, url, url_tt, start, end);
						if (url) gf_free(url);
						if (url_tt) gf_free(url_tt);
					}
					else if (!stricmp(sub->name, "karaoke")) {
						u32 time = 0;
						GF_XMLNode *krok;
						m=0;
						while ((att=(GF_XMLAttribute *)gf_list_enum(sub->attributes, &m))) {
							if (!strcmp(att->name, "startTime")) time = atoi(att->value);
						}
						gf_isom_text_add_karaoke(samp, time);
						m=0;
						while ((krok=(GF_XMLNode*)gf_list_enum(sub->content, &m))) {
							u32 u=0;
							if (krok->type) continue;
							if (strcmp(krok->name, "run")) continue;
							start = end = 0;
							while ((att=(GF_XMLAttribute *)gf_list_enum(krok->attributes, &u))) {
								if (!strcmp(att->name, "startMarker")) GET_MARKER_POS(start, 0)
									else if (!strcmp(att->name, "endMarker")) GET_MARKER_POS(end, 1)
										else if (!strcmp(att->name, "duration")) time += atoi(att->value);
							}
							gf_isom_text_set_karaoke_segment(samp, time, start, end);
						}
					}
				}
			}
		}
		/*OK, let's add the sample*/
		if (samp) {
			if (!same_box) gf_isom_text_set_box(samp, td.default_pos.top, td.default_pos.left, td.default_pos.bottom, td.default_pos.right);
//			if (!same_style) gf_isom_text_add_style(samp, &td.default_style);

			txtin_process_send_text_sample(ctx, samp, ctx->start, duration, isRAP);
			ctx->start += duration;
			gf_isom_delete_text_sample(samp);

		}
	}

	return GF_EOS;
}


GF_Err gf_import_timed_text(GF_MediaImporter *import)
{
	return GF_NOT_SUPPORTED;
}

static GF_Err txtin_process(GF_Filter *filter)
{
	GF_TXTIn *ctx = gf_filter_get_udta(filter);
	GF_FilterPacket *pck;
	GF_Err e;
	Bool start, end;
	pck = gf_filter_pid_get_packet(ctx->ipid);
	if (!pck) {
		return GF_OK;
	}
	gf_filter_pck_get_framing(pck, &start, &end);
	if (!end) {
		gf_filter_pid_drop_packet(ctx->ipid);
		return GF_OK;
	}
	//file is loaded

	e = ctx->text_process(filter, ctx);
	if (e==GF_EOS) {
		gf_filter_pid_drop_packet(ctx->ipid);
		if (gf_filter_pid_is_eos(ctx->ipid))
			gf_filter_pid_set_eos(ctx->opid);
	}
	return e;
}

static GF_Err txtin_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{
	GF_Err e;
	const char *src = NULL;
	GF_TXTIn *ctx = gf_filter_get_udta(filter);
	const GF_PropertyValue *prop;

	if (is_remove) {
		ctx->ipid = NULL;
		return GF_OK;
	}

	if (! gf_filter_pid_check_caps(pid))
		return GF_NOT_SUPPORTED;

	//we must have a file path
	prop = gf_filter_pid_get_property(pid, GF_PROP_PID_FILEPATH);
	if (prop && prop->value.string) src = prop->value.string;
	if (!src)
		return GF_NOT_SUPPORTED;

	if (!ctx->ipid) {
		GF_FilterEvent fevt;
		ctx->ipid = pid;

		//we work with full file only, send a play event on source to indicate that
		GF_FEVT_INIT(fevt, GF_FEVT_PLAY, pid);
		fevt.play.start_range = 0;
		fevt.base.on_pid = ctx->ipid;
		fevt.play.full_file_only = GF_TRUE;
		gf_filter_pid_send_event(ctx->ipid, &fevt);
		ctx->file_name = src;
	} else {
		if (pid != ctx->ipid) {
			return GF_REQUIRES_NEW_INSTANCE;
		}
		if (!strcmp(ctx->file_name, src)) return GF_OK;
		//TODO reset context
		ctx->is_setup = GF_FALSE;

		ctx->file_name = src;
	}
	//guess type
	e = gf_text_guess_format(ctx->file_name, &ctx->fmt);
	if (e) return e;
	if (!ctx->fmt) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_PARSER, ("[TXTLoad] Unknown text format for %s\n", ctx->file_name));
		return GF_NOT_SUPPORTED;
	}

	if (ctx->webvtt && (ctx->fmt == GF_TEXT_IMPORT_SRT))
		ctx->fmt = GF_TEXT_IMPORT_WEBVTT;

	switch (ctx->fmt) {
	case GF_TEXT_IMPORT_SRT:
		ctx->text_process = txtin_process_srt;
		break;
#ifndef GPAC_DISABLE_VTT
	case GF_TEXT_IMPORT_WEBVTT:
		ctx->text_process = txtin_process_webvtt;
		break;
#endif
	case GF_TEXT_IMPORT_TTXT:
		ctx->text_process = txtin_process_ttxt;
		break;
	case GF_TEXT_IMPORT_TEXML:
		ctx->text_process = txtin_process_texml;
		break;
	case GF_TEXT_IMPORT_SUB:
		ctx->text_process = gf_text_process_sub;
		break;

/*	case GF_TEXT_IMPORT_SWF_SVG:
		return gf_text_import_swf(import);
	case GF_TEXT_IMPORT_TTML:
		return gf_text_import_ttml(import);
*/
	default:
		return GF_BAD_PARAM;
	}

	return GF_OK;
}

static Bool txtin_process_event(GF_Filter *filter, const GF_FilterEvent *com)
{
	GF_TXTIn *ctx = gf_filter_get_udta(filter);
	switch (com->base.type) {
	case GF_FEVT_PLAY:
		//cancel play event, we work with full file
		return GF_TRUE;
	default:
		return GF_FALSE;
	}
	return GF_FALSE;
}

GF_Err txtin_initialize(GF_Filter *filter)
{
	char data[1];
	GF_TXTIn *ctx = gf_filter_get_udta(filter);
	ctx->bs_w = gf_bs_new(data, 1, GF_BITSTREAM_WRITE);
	return GF_OK;
}
void txtin_finalize(GF_Filter *filter)
{
	GF_TXTIn *ctx = gf_filter_get_udta(filter);

	if (ctx->samp) gf_isom_delete_text_sample(ctx->samp);
	if (ctx->src) gf_fclose(ctx->src);
	if (ctx->bs_w) gf_bs_del(ctx->bs_w);
	if (ctx->vttparser) gf_webvtt_parser_del(ctx->vttparser);
	if (ctx->parser) gf_xml_dom_del(ctx->parser);
	if (ctx->text_descs) {
		while (gf_list_count(ctx->text_descs)) {
			GF_PropertyValue *p = gf_list_pop_back(ctx->text_descs);
			gf_free(p->value.data.ptr);
			gf_free(p);
		}
		gf_list_del(ctx->text_descs);
	}

}

static const GF_FilterCapability TXTInInputs[] =
{
	CAP_INC_STRING(GF_PROP_PID_MIME, "x-subtitle/srt|subtitle/srt|text/srt"),
	CAP_INC_STRING(GF_PROP_PID_MIME, "x-subtitle/sub|subtitle/sub|text/sub"),
	CAP_INC_STRING(GF_PROP_PID_MIME, "x-subtitle/ttxt|subtitle/ttxt|text/ttxt"),
	CAP_INC_STRING(GF_PROP_PID_MIME, "x-subtitle/vtt|subtitle/vtt|text/vtt"),
	CAP_INC_STRING(GF_PROP_PID_MIME, "x-quicktime/text"),
	CAP_INC_STRING(GF_PROP_PID_MIME, "subtitle/ttml|text/ttml|application/xml+ttml"),
	{},
	CAP_INC_STRING(GF_PROP_PID_FILE_EXT, "srt|ttxt|sub|vtt|txml|ttml"),
	{},
};

static const GF_FilterCapability TXTInOutputs[] =
{
	CAP_INC_UINT(GF_PROP_PID_STREAM_TYPE, GF_STREAM_TEXT),
	CAP_INC_UINT(GF_PROP_PID_OTI, GPAC_OTI_TEXT_MPEG4),
};


#define OFFS(_n)	#_n, offsetof(GF_TXTIn, _n)

static const GF_FilterArgs TXTInArgs[] =
{
	{ OFFS(webvtt), "force WebVTT import of SRT files", GF_PROP_BOOL, "false", NULL, GF_FALSE},
	{ OFFS(nodefbox), "skip default text box", GF_PROP_BOOL, "false", NULL, GF_FALSE},
	{ OFFS(noflush), "skip final sample flush for srt", GF_PROP_BOOL, "false", NULL, GF_FALSE},
	{ OFFS(fontname), "default font to use", GF_PROP_STRING, NULL, NULL, GF_FALSE},
	{ OFFS(fontsize), "default font size", GF_PROP_UINT, "0", NULL, GF_FALSE},
	{ OFFS(lang), "default language to use", GF_PROP_STRING, NULL, NULL, GF_FALSE},
	{ OFFS(width), "default width of text area, set to 0 to resolve against visual PIDs", GF_PROP_UINT, "0", NULL, GF_FALSE},
	{ OFFS(height), "default height of text area, set to 0 to resolve against visual PIDs", GF_PROP_UINT, "0", NULL, GF_FALSE},
	{ OFFS(x), "default horizontal offset of text area", GF_PROP_UINT, "0", NULL, GF_FALSE},
	{ OFFS(y), "default vertical offset of text area", GF_PROP_UINT, "0", NULL, GF_FALSE},
	{ OFFS(zorder), "default z-order of the PID", GF_PROP_SINT, "0", NULL, GF_FALSE},
	{ OFFS(timescale), "default timescale of the PID", GF_PROP_UINT, "1000", NULL, GF_FALSE},
	{}
};

GF_FilterRegister TXTInRegister = {
	.name = "ttxtload",
	.description = "Timed text loader (SRT/SUB/TTXT/WebVTT/TTML)",
	.private_size = sizeof(GF_TXTIn),
	.requires_main_thread = GF_TRUE,
	.args = TXTInArgs,
	INCAPS(TXTInInputs),
	OUTCAPS(TXTInOutputs),
	.process = txtin_process,
	.configure_pid = txtin_configure_pid,
	.process_event = txtin_process_event,
	.initialize = txtin_initialize,
	.finalize = txtin_finalize
};


const GF_FilterRegister *txtin_register(GF_FilterSession *session)
{
	return &TXTInRegister;
}
