/* packet-bson.c
 * BSON dissector for wireshark
 * Based on mongo dissector
 * Copyright 2014, RayXXZhang <123hurray@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-tcp.h>


/* BSON Element types */
/* See http://bsonspec.org/#/specification for detail */
#define BSON_ELEMENT_TYPE_DOUBLE         1
#define BSON_ELEMENT_TYPE_STRING         2
#define BSON_ELEMENT_TYPE_DOC            3
#define BSON_ELEMENT_TYPE_ARRAY          4
#define BSON_ELEMENT_TYPE_BINARY         5
#define BSON_ELEMENT_TYPE_UNDEF          6  /* Deprecated */
#define BSON_ELEMENT_TYPE_OBJ_ID         7
#define BSON_ELEMENT_TYPE_BOOL           8
#define BSON_ELEMENT_TYPE_DATETIME       9
#define BSON_ELEMENT_TYPE_NULL          10
#define BSON_ELEMENT_TYPE_REGEX         11
#define BSON_ELEMENT_TYPE_DB_PTR        12  /* Deprecated */
#define BSON_ELEMENT_TYPE_JS_CODE       13
#define BSON_ELEMENT_TYPE_SYMBOL        14
#define BSON_ELEMENT_TYPE_JS_CODE_SCOPE 15
#define BSON_ELEMENT_TYPE_INT32         16  /* 0x10 */
#define BSON_ELEMENT_TYPE_TIMESTAMP     17  /* 0x11 */
#define BSON_ELEMENT_TYPE_INT64         18  /* 0x12 */
#define BSON_ELEMENT_TYPE_MIN_KEY      255  /* 0xFF */
#define BSON_ELEMENT_TYPE_MAX_KEY      127  /* 0x7F */

static const value_string element_type_vals[] = {
  { BSON_ELEMENT_TYPE_DOUBLE,         "Double" },
  { BSON_ELEMENT_TYPE_STRING,         "String" },
  { BSON_ELEMENT_TYPE_DOC,            "Document" },
  { BSON_ELEMENT_TYPE_ARRAY,          "Array" },
  { BSON_ELEMENT_TYPE_BINARY,         "Binary" },
  { BSON_ELEMENT_TYPE_UNDEF,          "Undefined" },
  { BSON_ELEMENT_TYPE_OBJ_ID,         "Object ID" },
  { BSON_ELEMENT_TYPE_BOOL,           "Boolean" },
  { BSON_ELEMENT_TYPE_DATETIME,       "Datetime" },
  { BSON_ELEMENT_TYPE_NULL,           "NULL" },
  { BSON_ELEMENT_TYPE_REGEX,          "Regular Expression" },
  { BSON_ELEMENT_TYPE_DB_PTR,         "DBPointer" },
  { BSON_ELEMENT_TYPE_JS_CODE,        "JavaScript Code" },
  { BSON_ELEMENT_TYPE_SYMBOL,         "Symbol" },
  { BSON_ELEMENT_TYPE_JS_CODE_SCOPE,  "JavaScript Code w/Scope" },
  { BSON_ELEMENT_TYPE_INT32,          "Int32" },
  { BSON_ELEMENT_TYPE_TIMESTAMP,      "Timestamp" },
  { BSON_ELEMENT_TYPE_INT64,          "Int64" },
  { BSON_ELEMENT_TYPE_MIN_KEY,        "Min Key" },
  { BSON_ELEMENT_TYPE_MAX_KEY,        "Max Key" },
  { 0, NULL }
};

/* BSON Element Binary subtypes */
#define BSON_ELEMENT_BINARY_TYPE_GENERIC  0
#define BSON_ELEMENT_BINARY_TYPE_FUNCTION 1
#define BSON_ELEMENT_BINARY_TYPE_BINARY   2 /* OLD */
#define BSON_ELEMENT_BINARY_TYPE_UUID     3
#define BSON_ELEMENT_BINARY_TYPE_MD5      4
#define BSON_ELEMENT_BINARY_TYPE_USER   128 /* 0x80 */

static const value_string binary_type_vals[] = {
  { BSON_ELEMENT_BINARY_TYPE_GENERIC,  "Generic" },
  { BSON_ELEMENT_BINARY_TYPE_FUNCTION, "Function" },
  { BSON_ELEMENT_BINARY_TYPE_BINARY,   "Binary" },
  { BSON_ELEMENT_BINARY_TYPE_UUID,     "UUID" },
  { BSON_ELEMENT_BINARY_TYPE_MD5,      "MD5" },
  { BSON_ELEMENT_BINARY_TYPE_USER,     "User" },
  { 0, NULL }
};

void proto_reg_handoff_bson(void);


static int proto_bson = -1;

static int hf_bson = -1;
static int hf_bson_document = -1;
static int hf_bson_document_length = -1;
static int hf_bson_document_empty = -1;
static int hf_bson_elements = -1;
static int hf_bson_element_name = -1;
static int hf_bson_element_type = -1;
static int hf_bson_element_length = -1;
static int hf_bson_element_value_boolean = -1;
static int hf_bson_element_value_int32 = -1;
static int hf_bson_element_value_int64 = -1;
static int hf_bson_element_value_double = -1;
static int hf_bson_element_value_string = -1;
static int hf_bson_element_value_string_length = -1;
static int hf_bson_element_value_binary = -1;
static int hf_bson_element_value_binary_length = -1;
static int hf_bson_element_value_regex_pattern = -1;
static int hf_bson_element_value_regex_options = -1;
static int hf_bson_element_value_objectid = -1;
static int hf_bson_element_value_objectid_time = -1;
static int hf_bson_element_value_objectid_machine = -1;
static int hf_bson_element_value_objectid_pid = -1;
static int hf_bson_element_value_objectid_inc = -1;
static int hf_bson_element_value_db_ptr = -1;
static int hf_bson_element_value_js_code = -1;
static int hf_bson_element_value_js_scope = -1;
static int hf_bson_unknown = -1;



static gint ett_bson = -1;
static gint ett_bson_doc = -1;
static gint ett_bson_elements = -1;
static gint ett_bson_element = -1;
static gint ett_bson_objectid = -1;
static gint ett_bson_code = -1;
static gint ett_bson_fcn = -1;
static gint ett_bson_flags = -1;


#define BSON_MAX_NESTING 100
#define BSON_MAX_DOC_SIZE (16 * 1000 * 1000)



static int
dissect_bson_document(tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree, int hf_bson_doc, int nest_level)
{
  gint32 document_length;
  guint final_offset;
  proto_item *ti, *elements, *element, *objectid, *js_code, *js_scope;
  proto_tree *doc_tree, *elements_tree, *element_sub_tree, *objectid_sub_tree, *js_code_sub_tree, *js_scope_sub_tree;

  document_length = tvb_get_letohl(tvb, offset);

  ti = proto_tree_add_item(tree, hf_bson_doc, tvb, offset, document_length, ENC_NA);
  doc_tree = proto_item_add_subtree(ti, ett_bson_doc);

  proto_tree_add_item(doc_tree, hf_bson_document_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  if (nest_level > BSON_MAX_NESTING) {
      expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "BSON document recursion exceeds %u", BSON_MAX_NESTING);
      THROW(ReportedBoundsError);
  }

  if (document_length < 5) {
      expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "BSON document length too short: %u", document_length);
      THROW(ReportedBoundsError);
  }

  if (document_length > BSON_MAX_DOC_SIZE) {
      expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "BSON document length too long: %u", document_length);
      THROW(ReportedBoundsError);
  }

  if (document_length == 5) {
    /* document with length 5 is an empty document */
    /* don't display the element subtree */
    proto_tree_add_item(tree, hf_bson_document_empty, tvb, offset, document_length, ENC_NA);
    return document_length;
  }

  final_offset = offset + document_length;
  offset += 4;

  elements = proto_tree_add_item(doc_tree, hf_bson_elements, tvb, offset, document_length-5, ENC_NA);
  elements_tree = proto_item_add_subtree(elements, ett_bson_elements);

  do {
    /* Read document elements */
    guint8 e_type = -1;  /* Element type */
    gint str_len = -1;   /* String length */
    gint e_len = -1;     /* Element length */
    gint doc_len = -1;   /* Document length */

    e_type = tvb_get_guint8(tvb, offset);
    tvb_get_ephemeral_stringz(tvb, offset+1, &str_len);

    element = proto_tree_add_item(elements_tree, hf_bson_element_name, tvb, offset+1, str_len-1, ENC_UTF_8|ENC_NA);
    element_sub_tree = proto_item_add_subtree(element, ett_bson_element);
    proto_tree_add_item(element_sub_tree, hf_bson_element_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += str_len+1;

    switch(e_type) {
      case BSON_ELEMENT_TYPE_DOUBLE:
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
      case BSON_ELEMENT_TYPE_STRING:
      case BSON_ELEMENT_TYPE_JS_CODE:
      case BSON_ELEMENT_TYPE_SYMBOL:
        str_len = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len+4;
        break;
      case BSON_ELEMENT_TYPE_DOC:
      case BSON_ELEMENT_TYPE_ARRAY:
        offset += dissect_bson_document(tvb, pinfo, offset, element_sub_tree, hf_bson_document, nest_level+1);
        break;
      case BSON_ELEMENT_TYPE_BINARY:
        e_len = tvb_get_letohl(tvb, offset);
        /* TODO - Add functions to decode various binary subtypes */
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_binary_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_binary, tvb, offset+5, e_len, ENC_NA);
        offset += e_len+5;
        break;
      case BSON_ELEMENT_TYPE_UNDEF:
      case BSON_ELEMENT_TYPE_NULL:
      case BSON_ELEMENT_TYPE_MIN_KEY:
      case BSON_ELEMENT_TYPE_MAX_KEY:
        /* Nothing to do, as there is no element content */
        break;
      case BSON_ELEMENT_TYPE_OBJ_ID:
        objectid = proto_tree_add_item(element_sub_tree, hf_bson_element_value_objectid, tvb, offset, 12, ENC_NA);
        objectid_sub_tree = proto_item_add_subtree(objectid, ett_bson_objectid);
        /* Unlike most BSON elements, parts of ObjectID are stored Big Endian, so they can be compared bit by bit */
        proto_tree_add_item(objectid_sub_tree, hf_bson_element_value_objectid_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_bson_element_value_objectid_machine, tvb, offset+4, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_bson_element_value_objectid_pid, tvb, offset+7, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(objectid_sub_tree, hf_bson_element_value_objectid_inc, tvb, offset+9, 3, ENC_BIG_ENDIAN);
        offset += 12;
        break;
      case BSON_ELEMENT_TYPE_BOOL:
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_boolean, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
      case BSON_ELEMENT_TYPE_REGEX:
        /* regex pattern */
        tvb_get_ephemeral_stringz(tvb, offset, &str_len);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_regex_pattern, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        /* regex options */
        tvb_get_ephemeral_stringz(tvb, offset, &str_len);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_regex_options, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        break;
      case BSON_ELEMENT_TYPE_DB_PTR:
        str_len = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_db_ptr, tvb, offset, 12, ENC_NA);
        offset += 12;
        break;
      case BSON_ELEMENT_TYPE_JS_CODE_SCOPE:
        /* code_w_s ::= int32 string document */
        proto_tree_add_item(element_sub_tree, hf_bson_element_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        e_len = tvb_get_letohl(tvb, offset);
        offset += 4;
        str_len = tvb_get_letohl(tvb, offset);
        js_code = proto_tree_add_item(element_sub_tree, hf_bson_element_value_js_code, tvb, offset, str_len+4, ENC_NA);
        js_code_sub_tree = proto_item_add_subtree(js_code, ett_bson_code);
        proto_tree_add_item(js_code_sub_tree, hf_bson_element_value_string_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(js_code_sub_tree, hf_bson_element_value_string, tvb, offset+4, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len+4;
        doc_len = e_len - (str_len + 8);
        js_scope = proto_tree_add_item(element_sub_tree, hf_bson_element_value_js_scope, tvb, offset, doc_len, ENC_NA);
        js_scope_sub_tree = proto_item_add_subtree(js_scope, ett_bson_code);
        offset += dissect_bson_document(tvb, pinfo, offset, js_scope_sub_tree, hf_bson_document, nest_level+1);
        break;
      case BSON_ELEMENT_TYPE_INT32:
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_int32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
      case BSON_ELEMENT_TYPE_DATETIME:
      case BSON_ELEMENT_TYPE_TIMESTAMP:
        /* TODO Implement routine to convert datetime & timestamp values to UTC date/time */
        /* for now, simply display the integer value */
      case BSON_ELEMENT_TYPE_INT64:
        proto_tree_add_item(element_sub_tree, hf_bson_element_value_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
      default:
        break;
    }  /* end switch() */
  } while (offset < final_offset-1);

  return document_length;
}
static void
dissect_bson(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	if (tree) {
		dissect_bson_document(tvb, pinfo, 0, tree, hf_bson, 1);
	}
}

void
proto_register_bson(void)
{

  static hf_register_info hf[] = {
	{ &hf_bson,
      { "BSON", "bson.name",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bson_document,
      { "Document", "bson.document",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bson_document_length,
      { "Document length", "bson.document.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Length of BSON Document", HFILL }
    },
    { &hf_bson_document_empty,
      { "Empty Document", "bson.document.empty",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Document with no elements", HFILL }
    },
    { &hf_bson_elements,
      { "Elements", "bson.elements",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Document Elements", HFILL }
    },
    { &hf_bson_element_name,
      { "Element", "bson.element.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Element Name", HFILL }
    },
    { &hf_bson_element_type,
      { "Type", "bson.element.type",
      FT_UINT8, BASE_HEX_DEC, VALS(element_type_vals), 0x0,
      "Element Type", HFILL }
    },
    { &hf_bson_element_length,
      { "Length", "bson.element.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Element Length", HFILL }
    },
    { &hf_bson_element_value_boolean,
      { "Value", "bson.element.value",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_bson_element_value_int32,
      { "Value", "bson.element.value",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_bson_element_value_int64,
      { "Value", "bson.element.value",
      FT_INT64, BASE_DEC, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_bson_element_value_double,
      { "Value", "bson.element.value",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_bson_element_value_string,
      { "Value", "bson.element.value",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_bson_element_value_string_length,
      { "Length", "bson.element.value.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Element Value Length", HFILL }
    },
    { &hf_bson_element_value_binary,
      { "Value", "bson.element.value",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Element Value", HFILL }
    },
    { &hf_bson_element_value_binary_length,
      { "Length", "bson.element.value.length",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Binary Element Length", HFILL }
    },
    { &hf_bson_element_value_regex_pattern,
      { "Value", "bson.element.value.regex.pattern",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Regex Pattern", HFILL }
    },
    { &hf_bson_element_value_regex_options,
      { "Value", "bson.element.value.regex.options",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Regex Options", HFILL }
    },
    { &hf_bson_element_value_objectid,
      { "ObjectID", "bson.element.value.objectid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "ObjectID Value", HFILL }
    },
    { &hf_bson_element_value_objectid_time,
      { "ObjectID Time", "bson.element.value.objectid.time",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "ObjectID timestampt", HFILL }
    },
    { &hf_bson_element_value_objectid_machine,
      { "ObjectID Machine", "bson.element.value.objectid.machine",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      "ObjectID machine ID", HFILL }
    },
    { &hf_bson_element_value_objectid_pid,
      { "ObjectID PID", "bson.element.value.objectid.pid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "ObjectID process ID", HFILL }
    },
    { &hf_bson_element_value_objectid_inc,
      { "ObjectID inc", "bson.element.value.objectid.inc",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "ObjectID increment", HFILL }
    },
    { &hf_bson_element_value_db_ptr,
      { "ObjectID", "bson.element.value.db_ptr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "DBPointer", HFILL }
    },
    { &hf_bson_element_value_js_code,
      { "JavaScript code", "bson.element.value.js_code",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "JavaScript code to be evaluated", HFILL }
    },
    { &hf_bson_element_value_js_scope,
      { "JavaScript scope", "bson.element.value.js_scope",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Scope document for JavaScript evaluation", HFILL }
    },
    { &hf_bson_unknown,
      { "Unknown", "bson.unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Unknown Data type", HFILL }
    },
  };

  static gint *ett[] = {
    &ett_bson,
    &ett_bson_doc,
    &ett_bson_elements,
    &ett_bson_element,
    &ett_bson_objectid,
    &ett_bson_code,
    &ett_bson_fcn,
    &ett_bson_flags
  };
  proto_bson = proto_register_protocol("Binary JavaScript Object Notation", "BSON", "bson");
  proto_register_field_array(proto_bson, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("bson", dissect_bson, proto_bson);
}
void
proto_reg_handoff_bson(void)
{
  dissector_handle_t bson_handle;
  bson_handle = find_dissector("bson");
  dissector_add_string("media_type", "application/bson", bson_handle);
}